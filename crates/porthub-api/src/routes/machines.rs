use crate::{
    auth,
    domain::{enrollment, inventory, workspaces::object_id},
    error::{ApiError, ApiResult},
    input::{ApiBody, Model},
    store, App,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime, Document};
use rand::{distributions::Alphanumeric, Rng};
use serde_json::{json, Value};
use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/machines/list", get(list))
        .route("/api/machines/add", post(add))
        .route("/api/machines/groups/add", post(add_to_group))
        .route("/api/machines/groups/remove", post(remove_from_group))
        .route("/api/machines/refresh-token", post(refresh_token))
        .route("/api/machines/request-client-update", post(request_update))
        .route("/api/machines/{first}/{second}", get(pair))
}

async fn membership(
    app: &App,
    headers: &HeaderMap,
    raw: Value,
    remove: bool,
) -> ApiResult<Json<Value>> {
    let mut model = Model::new(raw)?;
    let machine = model.required_string("machine_id");
    let group = model.required_string("group_id");
    model.finish()?;
    let user = auth::current_user(app, headers).await?;
    let machine = object_id(&machine, "Invalid machine id")?;
    let group = object_id(&group, "Invalid group id")?;
    // Serialize membership changes with group deletion and mapped-port mutations.
    let _guard = app.connection_lock.lock().await;
    let filter = doc! {"_id":machine,"user_id":user.get("_id")};
    let mut record = app
        .collection("machines")
        .find_one(filter.clone())
        .await?
        .ok_or_else(|| ApiError::bad_request("Machine not found"))?;
    if record.contains_key("native_deletion") {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "Machine deletion is in progress",
        ));
    }
    if app
        .collection("machine_groups")
        .find_one(doc! {"_id":group,"user_id":user.get("_id")})
        .await?
        .is_none()
    {
        return Err(ApiError::bad_request("Group not found"));
    }
    let mut groups = inventory::group_ids(&record);
    let member = groups.contains(&group);
    if !remove && member {
        return Ok(Json(
            json!({"msg":"Machine is already in this group","data":inventory::machine(app,&record)}),
        ));
    }
    if remove && !member {
        // Legacy group_id can coexist with a nonempty modern group_ids array.
        let legacy = record.get_object_id("group_id").ok();
        if legacy != Some(group) {
            return Err(ApiError::bad_request("Machine is not in this group"));
        }
        let mut candidate = record.clone();
        candidate.remove("group_id");
        super::exit_nodes::validate_machine_changes(app, user.get("_id").ok_or_else(ApiError::unauthenticated)?, &[candidate]).await?;
        let now = DateTime::now();
        app.collection("machines")
            .update_one(
                filter,
                doc! {"$unset":{"group_id":""},"$set":{"updated_at":now}},
            )
            .await?;
        record.remove("group_id");
        record.insert("updated_at", now);
    } else {
        if remove {
            groups.retain(|id| *id != group);
        } else {
            groups.push(group);
        }
        let mut candidate = record.clone();
        candidate.insert("group_ids", &groups);
        candidate.remove("group_id");
        super::exit_nodes::validate_machine_changes(app, user.get("_id").ok_or_else(ApiError::unauthenticated)?, &[candidate]).await?;
        let now = DateTime::now();
        app.collection("machines")
            .update_one(
                filter,
                doc! {"$set":{"group_ids":&groups,"updated_at":now},"$unset":{"group_id":""}},
            )
            .await?;
        record.insert("group_ids", groups);
        record.remove("group_id");
        record.insert("updated_at", now);
    }
    app.notify_status(&record).await;
    let message = if remove {
        "Machine removed from group successfully"
    } else {
        "Machine added to group successfully"
    };
    Ok(Json(
        json!({"msg":message,"data":inventory::machine(app,&record)}),
    ))
}

async fn add_to_group(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    membership(&app, &headers, raw, false).await
}

async fn remove_from_group(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    membership(&app, &headers, raw, true).await
}

fn previous_log_tokens(machine: &Document) -> Vec<String> {
    let mut seen = BTreeSet::new();
    machine
        .get("token")
        .into_iter()
        .chain(machine.get_array("log_tokens").into_iter().flatten())
        .filter_map(Bson::as_str)
        .filter(|token| !token.is_empty() && seen.insert((*token).to_owned()))
        .take(5)
        .map(str::to_owned)
        .collect()
}

async fn refresh_token(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let mut model = Model::new(raw)?;
    let id = model.required_string("data_id");
    model.finish()?;
    let user = auth::current_user(&app, &headers).await?;
    let id = object_id(&id, "Invalid machine id")?;
    let _guard = app.connection_lock.lock().await;
    let filter = doc! {"_id":id,"user_id":user.get("_id")};
    let previous = app
        .collection("machines")
        .find_one(filter.clone())
        .await?
        .ok_or_else(|| ApiError::bad_request("Machine not found"))?;
    if previous.contains_key("native_deletion") {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "Machine deletion is in progress",
        ));
    }
    let token = new_token(&app).await?;
    let now = DateTime::now();
    let tokens = previous_log_tokens(&previous);
    let set = doc! {"token":&token,"log_tokens":&tokens,"updated_at":now};
    app.collection("machines")
        .update_one(filter.clone(), doc! {"$set":&set})
        .await?;
    if let Err(error) = crate::generated::rebuild(&app).await {
        // Preserve runtime sync/update writes that happened during publication.
        app.collection("machines")
            .update_one(
                doc! {"_id":id,"token":&token},
                crate::domain::machines::recovery(&previous, &set, &Document::new()),
            )
            .await?;
        // An error after rename (for example directory fsync) can occur after
        // publication, so also try to republish the restored credentials.
        if let Err(recovery) = crate::generated::rebuild(&app).await {
            tracing::error!(detail=%recovery.detail,"machine token configuration recovery failed");
        }
        return Err(error);
    }
    app.realtime.disconnect_machine(&id.to_hex());
    let mut updated = previous;
    updated.insert("token", token);
    updated.insert("log_tokens", tokens);
    updated.insert("updated_at", now);
    app.notify_config(&id.to_hex()).await;
    app.notify_status(&updated).await;
    Ok(Json(
        json!({"msg":"Machine token refreshed successfully","data":inventory::machine(&app,&updated)}),
    ))
}

async fn request_update(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let mut model = Model::new(raw)?;
    let id = model.required_string("data_id");
    model.finish()?;
    let user = auth::current_user(&app, &headers).await?;
    let id = object_id(&id, "Invalid machine id")?;
    app.artifacts.refresh_latest().await?;
    let latest_client_version = app.client_version();
    let mut bytes = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    let request = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let now = DateTime::now();
    let updated=app.collection("machines").find_one_and_update(
        doc! {"_id":id,"user_id":user.get("_id"),"deletion_pending":{"$ne":true},"native_deletion":{"$exists":false}},
        doc! {"$set":{"client_update_target_version":&latest_client_version,"client_update_request_id":request,
            "client_update_requested_at":now,"updated_at":now}})
        .return_document(mongodb::options::ReturnDocument::After).await?
        .ok_or_else(||ApiError::bad_request("Machine not found"))?;
    app.notify_config(&id.to_hex()).await;
    app.notify_status(&updated).await;
    Ok(Json(
        json!({"msg":"Machine client update requested successfully","data":inventory::machine(&app,&updated)}),
    ))
}

pub fn split_names(value: &str) -> ApiResult<(String, Vec<String>)> {
    let mut seen = BTreeSet::new();
    let mut names: Vec<String> = value
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty() && seen.insert(name.to_lowercase()))
        .map(|name| name.chars().take(64).collect())
        .collect();
    if names.is_empty() {
        return Err(ApiError::bad_request("Machine name is required"));
    }
    if names.len() > 11 {
        return Err(ApiError::bad_request("Use at most 10 aliases"));
    }
    let name = names.remove(0);
    Ok((name, names))
}

pub(crate) async fn valid_groups(
    app: &App,
    owner: &Bson,
    groups: Vec<String>,
) -> ApiResult<Vec<ObjectId>> {
    let mut ids = Vec::new();
    for group in groups {
        let group = group.trim();
        if group.is_empty() {
            continue;
        }
        let id = object_id(group, "Invalid group id")?;
        if app
            .collection("machine_groups")
            .find_one(doc! {"_id":id,"user_id":owner})
            .await?
            .is_none()
        {
            return Err(ApiError::bad_request("Group not found"));
        }
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    Ok(ids)
}

async fn new_token(app: &App) -> ApiResult<String> {
    loop {
        let token: String = rand::rngs::OsRng
            .sample_iter(&Alphanumeric)
            .take(48)
            .map(char::from)
            .collect();
        if app
            .collection("machines")
            .find_one(doc! {"token":&token})
            .await?
            .is_none()
        {
            return Ok(token);
        }
    }
}

async fn add(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let input = crate::domain::machines::parse(raw)?;
    let hostname = input.hostname.unwrap_or_default().trim().to_owned();
    let enabled = input.enabled.unwrap_or(true);
    let public_base = input.public_base.unwrap_or_default();
    let rathole = input.rathole.unwrap_or_default();
    let domain = input.domain.unwrap_or_default();
    let user = auth::current_user(&app, &headers).await?;
    let owner = user.get("_id").ok_or_else(ApiError::unauthenticated)?;
    let _guard = app.connection_lock.lock().await;
    let (name, aliases) = split_names(&input.name)?;
    let groups = valid_groups(&app, owner, input.groups.unwrap_or_default()).await?;
    let token = new_token(&app).await?;
    let now = DateTime::now();
    let id = ObjectId::new();
    let mut machine = doc! {"_id":id,"user_id":owner,"name":name,"aliases":aliases,
    "hostname":&hostname,"hostname_override":hostname,"client_hostname":"",
    "client_setup_public_base_url":public_base.trim(),"client_setup_rathole_server_address":rathole.trim(),
    "client_setup_service_domain":domain.trim(),"enabled":enabled,"local_ip":"","public_ip":"",
    "token":token,"log_tokens":[],"auth_required":false,"client_version":"",
    "client_update_target_version":"","client_update_request_id":"","client_update_last_handled_request_id":"",
    "client_update_requested_at":Bson::Null,"client_updated_at":Bson::Null,"last_seen_at":Bson::Null,
    "created_at":now,"updated_at":now};
    if !groups.is_empty() {
        machine.insert("group_ids", groups);
    }
    super::exit_nodes::validate_machine_changes(&app, owner, &[machine.clone()]).await?;
    app.collection("machines").insert_one(&machine).await?;
    if let Err(error) = enrollment::ensure(&app, &machine).await {
        app.collection("machines")
            .delete_one(doc! {"_id":id})
            .await?;
        return Err(error);
    }
    crate::generated::rebuild(&app).await?;
    app.notify_status(&machine).await;
    Ok(Json(
        json!({"msg":"Machine added successfully","data":inventory::machine(&app,&machine)}),
    ))
}

fn private_ips<'a>(peers: impl Iterator<Item = &'a Document>) -> Vec<String> {
    peers
        .filter_map(|peer| store::string(peer, "ip").parse::<std::net::Ipv4Addr>().ok())
        .filter(|address| address.is_private())
        .map(|address| address.to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

async fn list(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let user = auth::current_user(&app, &headers).await?;
    let owner = user.get("_id").ok_or_else(ApiError::unauthenticated)?;
    let machines: Vec<Document> = app
        .collection("machines")
        .find(doc! {"user_id":owner,"deletion_pending":{"$ne":true}})
        .sort(doc! {"created_at":1})
        .await?
        .try_collect()
        .await?;
    let peers: Vec<Document> = app
        .collection("private_peers")
        .find(doc! {"owner_id":owner,"enabled":true})
        .await?
        .try_collect()
        .await?;
    let mut by_machine: HashMap<String, Vec<&Document>> = HashMap::new();
    for peer in &peers {
        by_machine
            .entry(store::id(peer.get("machine_id")))
            .or_default()
            .push(peer);
    }
    let data: Vec<Value> = machines
        .iter()
        .map(|machine| {
            let mut value = inventory::machine(&app, machine);
            let ips = if machine.get_bool("private_owner_revoked").unwrap_or(false) {
                Vec::new()
            } else {
                private_ips(
                    by_machine
                        .get(&store::id(machine.get("_id")))
                        .into_iter()
                        .flatten()
                        .copied(),
                )
            };
            value["private_ips"] = json!(ips);
            value
        })
        .collect();
    Ok(Json(
        json!({"msg":"Machines listed successfully","data":data}),
    ))
}

fn history_days(query: &HashMap<String, String>) -> ApiResult<i64> {
    let Some(raw) = query.get("days") else {
        return Ok(365);
    };
    let days=raw.parse::<i64>().map_err(|_|ApiError::validation(vec![json!({"loc":["query","days"],"msg":"value is not a valid integer","type":"type_error.integer"})]))?;
    if !(1..=366).contains(&days) {
        let (message, kind, limit) = if days < 1 {
            (
                "ensure this value is greater than or equal to 1",
                "value_error.number.not_ge",
                1,
            )
        } else {
            (
                "ensure this value is less than or equal to 366",
                "value_error.number.not_le",
                366,
            )
        };
        return Err(ApiError::validation(vec![
            json!({"loc":["query","days"],"msg":message,"type":kind,"ctx":{"limit_value":limit}}),
        ]));
    }
    Ok(days)
}

async fn pair(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path((first, second)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> ApiResult<Json<Value>> {
    if second == "status-history" {
        return history(&app, &headers, &first, history_days(&query)?).await;
    }
    if first == "private-addresses" {
        return addresses(&app, &headers, &second).await;
    }
    if first == "command" {
        return Ok(Json(
            crate::enrollment_ticket::command(&app, &headers, &second, &query).await?,
        ));
    }
    Err(ApiError::new(StatusCode::NOT_FOUND, "Not Found"))
}

async fn addresses(app: &App, headers: &HeaderMap, id: &str) -> ApiResult<Json<Value>> {
    let user = auth::current_user(app, headers).await?;
    let id = object_id(id, "Invalid machine id")?;
    let machine = app
        .collection("machines")
        .find_one(doc! {"_id":id,"user_id":user.get("_id"),"deletion_pending":{"$ne":true}})
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Machine not found"))?;
    let ips = if machine.get_bool("private_owner_revoked").unwrap_or(false) {
        Vec::new()
    } else {
        let peers: Vec<Document> = app
            .collection("private_peers")
            .find(doc! {"machine_id":id,"owner_id":user.get("_id"),"enabled":true})
            .await?
            .try_collect()
            .await?;
        private_ips(peers.iter())
    };
    Ok(Json(json!({"data":ips})))
}

async fn history(app: &App, headers: &HeaderMap, id: &str, days: i64) -> ApiResult<Json<Value>> {
    let user = auth::current_user(app, headers).await?;
    let id = object_id(id, "Invalid machine id")?;
    let machine = app
        .collection("machines")
        .find_one(doc! {"_id":id,"user_id":user.get("_id")})
        .await?;
    let Some(machine) = machine else {
        return Ok(Json(json!({"msg":"Machine not found","data":[]})));
    };
    let since = DateTime::from_millis(DateTime::now().timestamp_millis() - days * 86_400_000);
    let events: Vec<Document> = app
        .collection("machine_status_events")
        .find(doc! {"machine_id":id,"changed_at":{"$gte":since}})
        .sort(doc! {"changed_at":1})
        .await?
        .try_collect()
        .await?;
    let previous = app
        .collection("machine_status_events")
        .find_one(doc! {"machine_id":id,"changed_at":{"$lt":since}})
        .sort(doc! {"changed_at":-1})
        .await?;
    let mut data = Vec::new();
    if let Some(previous) = previous {
        data.push(json!({"status":store::field(&previous,"status"),"changed_at":store::json(&Bson::DateTime(since))}));
    }
    data.extend(events.iter().map(|event|json!({"status":store::field(event,"status"),"changed_at":store::field(event,"changed_at")})));
    let status = if matches!(inventory::status(app, &machine), "online" | "auth_required") {
        "online"
    } else {
        "offline"
    };
    Ok(Json(
        json!({"msg":"Machine status history loaded successfully","data":data,"current_status":status}),
    ))
}
