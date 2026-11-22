//! Owner-managed, persistent SSH forwarding grants. Only the explicit credential
//! reveal response includes private key material. A disconnected grant has the
//! same stable endpoint and credentials when its holder reconnects.
use crate::{
    domain::workspaces::object_id,
    error::{ApiError, ApiResult},
    routes::access::browser,
    store, App,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode},
    routing::get,
    Json, Router,
};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, DateTime, Document};
use rand::seq::SliceRandom;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::HashSet, sync::Arc};

mod host_settings;
mod launcher;

pub const COLLECTION: &str = "ssh_port_forwards";

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/port-forwards", get(list).post(create))
        .route("/api/port-forwards/{id}", axum::routing::delete(remove).patch(host_settings::rename))
        .route("/api/port-forwards/{id}/public-ports", get(host_settings::list).post(host_settings::publish))
        .route("/api/port-forwards/{id}/public-ports/{port}", axum::routing::delete(host_settings::unpublish))
        .route("/api/port-forwards/{id}/launcher", get(launcher::download))
        .route("/api/port-forwards/{id}/audience", axum::routing::put(update_audience))
        .route(
            "/api/port-forwards/{id}/credentials",
            axum::routing::post(reveal),
        )
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NewEntry {
    name: String,
    #[serde(default)]
    public: bool,
    #[serde(default)]
    machine_ids: Vec<String>,
    #[serde(default)]
    group_ids: Vec<String>,
    mappings: Vec<Mapping>,
}

#[derive(Deserialize)]
#[serde(tag = "direction", rename_all = "lowercase", deny_unknown_fields)]
enum Mapping {
    Host {},
    Remote {
        #[serde(rename = "clientPort")]
        client_port: u16,
    },
    Local {
        #[serde(rename = "clientPort")]
        client_port: u16,
        #[serde(rename = "machineId")]
        machine_id: String,
        #[serde(rename = "servicePort")]
        service_port: u16,
    },
}

fn ids(raw: &[String]) -> ApiResult<Vec<ObjectId>> {
    if raw.len() > 128 {
        return Err(ApiError::bad_request(
            "Select up to 128 machines or groups.",
        ));
    }
    raw.iter()
        .map(|s| object_id(s, "Invalid machine or group."))
        .collect::<ApiResult<HashSet<_>>>()
        .map(|set| set.into_iter().collect())
}

async fn check_inventory(
    app: &App,
    collection: &str,
    owner: ObjectId,
    ids: &[ObjectId],
) -> ApiResult<()> {
    if ids.is_empty() {
        return Ok(());
    }
    let mut filter = doc! {"_id":{"$in":ids}, "user_id":owner};
    if collection == "machines" {
        filter.extend(doc! {"kind":{"$ne":"virtual_host"}, "deletion_pending":{"$ne":true}});
    }
    if app.collection(collection).count_documents(filter).await? != ids.len() as u64 {
        return Err(ApiError::bad_request(
            "Select machines and groups from this account.",
        ));
    }
    Ok(())
}

fn validate(input: &NewEntry) -> ApiResult<()> {
    if input.name.trim().is_empty() || input.name.chars().count() > 80 {
        return Err(ApiError::bad_request(
            "Enter a name of up to 80 characters.",
        ));
    }
    if !(1..=32).contains(&input.mappings.len()) {
        return Err(ApiError::bad_request("Choose 1–32 port mappings."));
    }
    let host_mode = input.mappings.iter().any(|m| matches!(m, Mapping::Host {}));
    if host_mode && (input.mappings.len() != 1 || input.public) {
        return Err(ApiError::bad_request("A host forward uses one private host mapping."));
    }
    let mut local = HashSet::new();
    let mut remote = HashSet::new();
    for mapping in &input.mappings {
        match mapping {
            Mapping::Local {
                client_port,
                service_port,
                machine_id,
            } => {
                object_id(machine_id, "Choose a registered destination machine.")?;
                if *client_port == 0 || *service_port == 0 || !local.insert(client_port) {
                    return Err(ApiError::bad_request(
                        "Local listeners need distinct, nonzero TCP ports.",
                    ));
                }
            }
            Mapping::Remote { client_port } if *client_port == 0 || !remote.insert(client_port) => {
                return Err(ApiError::bad_request(
                    "Shared ports must be distinct, nonzero TCP ports.",
                ))
            }
            _ => (),
        }
    }
    let selected = !input.machine_ids.is_empty() || !input.group_ids.is_empty();
    if !host_mode && remote.is_empty() && (input.public || selected) {
        return Err(ApiError::bad_request(
            "Exposure applies only to ports shared from this computer.",
        ));
    }
    if input.public && selected {
        return Err(ApiError::bad_request(
            "Public forwards cannot restrict access by private machine or group.",
        ));
    }
    Ok(())
}

fn unavailable<E: std::fmt::Display>(err: E) -> ApiError {
    tracing::warn!(error=%err,"SSH forward provisioning is unavailable");
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "SSH forwarding is unavailable. Try again after the gateway reconnects.",
    )
}

async fn owner(app: &App, headers: &HeaderMap, method: Method) -> ApiResult<ObjectId> {
    // Also protect credential reads in browsers if the portal's other API routes support CORS.
    crate::routes::access::check_origin(headers, &Method::POST)?;
    Ok(browser(app, headers, &method, "", true).await?.1)
}
async fn choices(app: &App, owner: ObjectId, collection: &str) -> ApiResult<Vec<Value>> {
    let mut filter = doc! {"user_id":owner};
    if collection == "machines" {
        filter.extend(doc! {"kind":{"$ne":"virtual_host"}, "deletion_pending":{"$ne":true}});
    }
    let rows: Vec<Document> = app
        .collection(collection)
        .find(filter)
        .projection(doc! {"name":1})
        .sort(doc! {"name":1,"_id":1})
        .await?
        .try_collect()
        .await?;
    Ok(rows
        .iter()
        .map(|row| json!({"id":store::id(row.get("_id")), "name":store::string(row,"name")}))
        .collect())
}
fn summary(row: &Document) -> Value {
    json!({"id":store::id(row.get("_id")), "name":store::string(row,"name"), "public":row.get_bool("public").unwrap_or(false),
        "published":row.get_bool("public").unwrap_or(false) || row.get_array("machine_ids").is_ok_and(|v| !v.is_empty()) || row.get_array("group_ids").is_ok_and(|v| !v.is_empty()),
        "mappings":store::field(row,"mappings"), "machineIds":store::field(row,"machine_ids"), "groupIds":store::field(row,"group_ids")})
}
async fn list(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let owner = owner(&app, &headers, Method::GET).await?;
    let (rows, machines, groups) = tokio::try_join!(
        async {
            Ok::<_, ApiError>(
                app.collection(COLLECTION)
                    .find(doc! {"workspace_id":owner,"state":"active"})
                    .sort(doc! {"_id":-1})
                    .await?
                    .try_collect::<Vec<Document>>()
                    .await?,
            )
        },
        choices(&app, owner, "machines"),
        choices(&app, owner, "machine_groups")
    )?;
    let suffix = if rows.is_empty() {
        String::new()
    } else {
        crate::port_forward_bridge::workspace_suffix(&app, owner).await?
    };
    let entries: Vec<_> = rows
        .iter()
        .map(|row| {
            let mut entry = summary(row);
            entry["status"] = match crate::port_forward_bridge::status_from_row(&app, row, &suffix)
            {
                Ok(status) => json!(status),
                Err(_) => json!({"ready":false,"reason":"Gateway status unavailable"}),
            };
            entry
        })
        .collect();
    Ok(Json(
        json!({"entries":entries,"machines":machines,"groups":groups}),
    ))
}

// Use the same unique index as ordinary agent port mappings. The disabled
// reservations have no machine or user id, so they never enter tunnel configs.
async fn reserve(app: &App, owner: ObjectId, id: ObjectId, count: usize) -> ApiResult<Vec<u16>> {
    reserve_with(app, owner, id, count, &Document::new()).await
}
async fn reserve_with(app: &App, owner: ObjectId, id: ObjectId, count: usize, fields: &Document) -> ApiResult<Vec<u16>> {
    if count == 0 {
        return Ok(Vec::new());
    }
    super::connections::ensure_index(app).await?;
    let (first, last) = app.config.external_port_range.unwrap_or((10000, 65535));
    let mut candidates: Vec<_> = (first.max(1024)..=last).collect();
    candidates.shuffle(&mut rand::thread_rng());
    let mut result = Vec::new();
    for port in candidates {
        let mut reservation = fields.clone();
        reservation.extend(doc!{"external_port":i32::from(port),"enabled":false,"forward_reservation":id,"forward_owner":owner});
        match app.collection("connections").insert_one(reservation).await {
            Ok(_) => {result.push(port); if result.len() == count {return Ok(result);} }
            Err(e) if store::duplicate(&e) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(ApiError::new(
        StatusCode::CONFLICT,
        "No forwarding ports available in the gateway range.",
    ))
}

async fn create(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(input): Json<NewEntry>,
) -> ApiResult<Json<Value>> {
    let owner = owner(&app, &headers, Method::POST).await?;
    validate(&input)?;
    let clients = ids(&input.machine_ids)?;
    let groups = ids(&input.group_ids)?;
    let mut all: HashSet<_> = clients.iter().copied().collect();
    for m in &input.mappings {
        if let Mapping::Local { machine_id, .. } = m {
            all.insert(object_id(machine_id, "Invalid machine.")?);
        }
    }
    let all: Vec<_> = all.into_iter().collect();
    check_inventory(&app, "machines", owner, &all).await?;
    check_inventory(&app, "machine_groups", owner, &groups).await?;
    let id = ObjectId::new();
    crate::port_forward_auth::endpoint(&app).map_err(unavailable)?;
    let (_, key) = app
        .forward_keys()
        .await
        .map_err(unavailable)?
        .credentials(&owner.to_hex(), &id.to_hex())
        .map_err(unavailable)?;
    let count = input
        .mappings
        .iter()
        .filter(|m| matches!(m, Mapping::Remote { .. } | Mapping::Host {}))
        .count();
    let guard = app.connection_lock.lock().await;
    if app
        .collection(COLLECTION)
        .count_documents(doc! {"workspace_id":owner})
        .await?
        >= 64
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "Delete an unused forward before creating another.",
        ));
    }
    app.collection(COLLECTION).insert_one(doc!{"_id":id, "workspace_id":owner, "state":"provisioning","created_at":DateTime::now(),
        "public_key":key, "name":input.name.trim(), "public":input.public,"machine_ids":clients,"group_ids":groups}).await?;
    let saved = async {
        if count > 0 {
            crate::port_forward_bridge::private::ensure_identity(&app,owner,&doc!{"_id":id},&[]).await?;
        }
        let ports = reserve(&app,owner,id,count).await?;
        let mut ports = ports.into_iter();
        let mappings:Vec<_> = input.mappings.into_iter().map(|m|match m {
            Mapping::Host{}=>doc!{"direction":"host","gatewayPort":i32::from(ports.next().expect("one reserved port per host mapping"))},
            Mapping::Remote{client_port}=>doc!{"direction":"remote","clientPort":i32::from(client_port),"gatewayPort":i32::from(ports.next().expect("one reserved port per remote mapping"))},
            Mapping::Local{client_port,service_port,machine_id}=>doc!{"direction":"local","clientPort":i32::from(client_port),"servicePort":i32::from(service_port),"target":format!("host-{}",machine_id.to_lowercase()),"machineId":machine_id.to_lowercase()},
        }).collect();
        app.collection(COLLECTION).update_one(doc!{"_id":id},doc!{"$set":{"state":"active","mappings":mappings}}).await?;
        Ok::<_,ApiError>(())
    }.await;
    drop(guard);
    let saved = match saved {
        Ok(()) => crate::port_forward_bridge::activate(&app, owner, id)
            .await
            .map_err(unavailable),
        Err(e) => Err(e),
    };
    if let Err(error) = saved {
        retire(&app, owner, id).await?;
        return Err(error);
    }
    Ok(Json(json!({"id":id.to_hex()})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Audience {
    public: bool,
    #[serde(default)]
    machine_ids: Vec<String>,
    #[serde(default)]
    group_ids: Vec<String>,
}

async fn update_audience(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<Audience>,
) -> ApiResult<Json<Value>> {
    let owner = owner(&app, &headers, Method::PUT).await?;
    let id = object_id(&id, "Invalid forward.")?;
    let clients = ids(&input.machine_ids)?;
    let groups = ids(&input.group_ids)?;
    if input.public && (!clients.is_empty() || !groups.is_empty()) {
        return Err(ApiError::bad_request("Public forwards cannot restrict access by private machine or group."));
    }
    // Serialize with creation/deletion; no credentials or mapping fields are writable.
    let _guard = app.connection_lock.lock().await;
    let filter = doc! {"_id":id,"workspace_id":owner,"state":"active"};
    let row = app.collection(COLLECTION).find_one(filter.clone()).await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Forward not found."))?;
    check_inventory(&app, "machines", owner, &clients).await?;
    check_inventory(&app, "machine_groups", owner, &groups).await?;

    let host_mode = row.get_array("mappings").is_ok_and(|items| items.iter().any(|m|
        m.as_document().is_some_and(|m| m.get_str("direction") == Ok("host"))));
    if host_mode && input.public {
        return Err(ApiError::bad_request("Publish individual host ports separately."));
    }
    let remote = row.get_array("mappings").is_ok_and(|items| items.iter().any(|m|
        m.as_document().is_some_and(|m| m.get_str("direction") == Ok("remote"))));
    if !host_mode && !remote && (input.public || !clients.is_empty() || !groups.is_empty()) {
        return Err(ApiError::bad_request("Exposure applies only to ports shared from this computer."));
    }
    let same_ids = |key: &str, expected: &[ObjectId]| {
        row.get_array(key).ok().and_then(|items| items.iter()
            .map(|item| item.as_object_id()).collect::<Option<HashSet<_>>>())
            == Some(expected.iter().copied().collect())
    };
    if row.get_bool("audience_cleanup_pending") != Ok(true)
        && row.get_bool("public") == Ok(input.public)
        && same_ids("machine_ids", &clients) && same_ids("group_ids", &groups)
    {
        return Ok(Json(json!({"id":id.to_hex()})));
    }
    // Withdraw before touching listeners. A reconciliation failure leaves an
    // unpublished entry with its original credentials and reserved port intact.
    app.collection(COLLECTION).update_one(filter.clone(), doc!{"$set":{
        "public":false,"machine_ids":[],"group_ids":[],
        "audience_cleanup_pending":row.get_bool("public")==Ok(true) || row.get_bool("audience_cleanup_pending")==Ok(true)}}).await?;
    crate::port_forward_bridge::withdraw_audience(&app, owner, id, &row)
        .await.map_err(unavailable)?;
    let changed = app.collection(COLLECTION).update_one(filter.clone(), doc!{"$set":{
        "public":input.public,"machine_ids":clients,"group_ids":groups},"$unset":{"audience_cleanup_pending":""}}).await?;
    if changed.matched_count == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Forward not found."));
    }
    if let Err(error) = crate::port_forward_bridge::activate(&app, owner, id).await {
        app.collection(COLLECTION).update_one(filter, doc!{"$set":{
            "public":false,"machine_ids":[],"group_ids":[],"audience_cleanup_pending":input.public}}).await?;
        crate::port_forward_bridge::withdraw_audience(&app, owner, id,
            &doc!{"public":input.public,"mappings":row.get_array("mappings").cloned().unwrap_or_default()})
            .await.map_err(unavailable)?;
        app.collection(COLLECTION).update_one(doc!{"_id":id,"workspace_id":owner},
            doc!{"$unset":{"audience_cleanup_pending":""}}).await?;
        return Err(unavailable(error));
    }
    Ok(Json(json!({"id":id.to_hex()})))
}

async fn reveal(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<impl axum::response::IntoResponse> {
    let owner = owner(&app, &headers, Method::POST).await?;
    let id = object_id(&id, "Invalid forward.")?;
    let row = app
        .collection(COLLECTION)
        .find_one(doc! {"_id":id,"workspace_id":owner,"state":"active"})
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Forward not found."))?;
    let master = app.forward_keys().await.map_err(unavailable)?;
    let (pem, public_key) = master
        .credentials(&owner.to_hex(), &id.to_hex())
        .map_err(unavailable)?;
    if row.get_str("public_key") != Ok(public_key.as_str()) {
        return Err(unavailable("forward signing key mismatch"));
    }
    let (gateway, port) = crate::port_forward_auth::endpoint(&app).map_err(unavailable)?;
    let launcher_token = launcher::token(master,owner,id)?;
    Ok(([(axum::http::header::CACHE_CONTROL,"private, no-store")], Json(
        json!({"launcherToken":launcher_token,"gateway":gateway,"sshPort":port,"username":format!("pf-{}",id.to_hex()),
        "hostKey":master.host_public_key().map_err(unavailable)?,"fingerprint":master.host_fingerprint(),
        "privateKey":pem.as_str(),"mappings":store::field(&row,"mappings")}),
    )))
}

pub(crate) async fn retire(app: &App, owner: ObjectId, id: ObjectId) -> ApiResult<()> {
    let filter = doc! {"_id":id,"workspace_id":owner};
    let result = app
        .collection(COLLECTION)
        .update_one(filter.clone(), doc! {"$set":{"state":"deleting"}})
        .await?;
    if result.matched_count == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Forward not found."));
    }
    app.forward_registry.revoke(&id.to_hex());
    crate::port_forward_bridge::deactivate(app, owner, id)
        .await
        .map_err(unavailable)?;
    app.collection("connections")
        .delete_many(doc! {"forward_reservation":id,"forward_owner":owner})
        .await?;
    app.collection(COLLECTION).delete_one(filter).await?;
    Ok(())
}
async fn remove(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let owner = owner(&app, &headers, Method::DELETE).await?;
    let _guard = app.connection_lock.lock().await;
    retire(&app, owner, object_id(&id, "Invalid forward.")?).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_profiles_accept_only_an_isolated_private_host_mapping() {
        let valid=|body| validate(&serde_json::from_value::<NewEntry>(body).unwrap()).is_ok();
        assert!(valid(json!({"name":"Lab","mappings":[{"direction":"host"}]})));
        assert!(valid(json!({"name":"Lab","machineIds":["1234567890abcdef12345678"],"mappings":[{"direction":"host"}]})));
        assert!(!valid(json!({"name":"Lab","public":true,"mappings":[{"direction":"host"}]})));
        assert!(!valid(json!({"name":"Lab","mappings":[{"direction":"host"},{"direction":"remote","clientPort":22}]})));
        assert!(serde_json::from_value::<NewEntry>(json!({"name":"Lab","mappings":[{"direction":"host","target":"10.0.0.1"}]})).is_err());
    }

    #[test]
    fn unpublished_remote_mapping_and_audience_edit_contract() {
        let entry: NewEntry = serde_json::from_value(json!({
            "name":"Unpublished", "mappings":[{"direction":"remote","clientPort":22}]
        })).unwrap();
        assert!(validate(&entry).is_ok());
        assert!(serde_json::from_value::<Audience>(json!({
            "public":false,"gatewayPort":1234
        })).is_err());
        assert!(serde_json::from_value::<Audience>(json!({
            "public":false,"mappings":[]
        })).is_err());
    }
}
