//! Browser private-access inventory. Credential material is explicitly excluded
//! from every response; workspace authorization precedes inventory queries.
use crate::{
    domain::{enrollment, inventory, private_names},
    error::{ApiError, ApiResult},
    input::{ApiBody, Model},
    routes::access::{browser, WorkspaceQuery},
    store, App,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode},
    routing::{get, put},
    Json, Router,
};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, Bson, DateTime, Document};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/access/snapshot", get(snapshot))
        .route("/api/access/network", put(network))
        .route(
            "/api/access/private/peers/{id}",
            put(change_peer).delete(revoke_peer),
        )
}

async fn change_peer(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>,
    Path(id): Path<String>,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let mut model = Model::new(raw)?;
    let enabled = model.required_bool("enabled");
    model.finish()?;
    let (_, owner, _) = browser(&app, &headers, &Method::PUT, &query.workspace, true).await?;
    let changed = app
        .collection("private_peers")
        .update_one(
            doc! {"_id":id,"workspace_id":owner},
            doc! {"$set":{"enabled":enabled,"updated_at":DateTime::now()}},
        )
        .await?;
    if changed.matched_count == 0 {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Private peer not found",
        ));
    }
    Ok(Json(
        json!({"msg":if enabled {"Private access enabled"} else {"Private access disabled"}}),
    ))
}

async fn revoke_peer(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let (user, owner, role) =
        browser(&app, &headers, &Method::DELETE, &query.workspace, false).await?;
    let mut filter = doc! {"_id":&id,"workspace_id":owner};
    if role != "owner" && role != "admin" {
        filter.insert("owner_id", user.get("_id").cloned().unwrap_or(Bson::Null));
    }
    // Credential invalidation happens before cleanup, so retained queue records
    // cannot authenticate a revoked peer if a later cleanup operation fails.
    let changed = app.collection("private_peers").update_one(filter,
        doc!{"$set":{"enabled":false},"$unset":{"credential_hash":"","fingerprint":"","instance":""}}).await?;
    if changed.matched_count == 0 {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Private peer not found",
        ));
    }
    app.collection("private_install_tickets")
        .update_many(
            doc! {"peer_id":&id},
            doc! {"$set":{"consumed_at":DateTime::now()}},
        )
        .await?;
    app.collection("private_signals")
        .delete_many(doc! {"$or":[{"from":&id},{"to":&id}]})
        .await?;
    Ok(Json(
        json!({"msg":"Private credential revoked; public access is unchanged"}),
    ))
}

async fn network(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let (network, suffix) = enrollment::preferences_value(raw)?;
    let (_, owner, _) = browser(&app, &headers, &Method::PUT, &query.workspace, true).await?;
    app.collection("private_networks")
        .update_one(
            doc! {"_id":owner.to_hex()},
            doc! {"$set":{"cidr":network.cidr(),"dns_suffix":&suffix,"updated_at":DateTime::now()}},
        )
        .upsert(true)
        .await?;
    Ok(Json(
        json!({"data":{"cidr":network.cidr(),"dns_suffix":suffix},"transport_ready":false}),
    ))
}

async fn snapshot(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>,
) -> ApiResult<Json<Value>> {
    let (_, owner, role) = browser(&app, &headers, &Method::GET, &query.workspace, false).await?;
    let machines: Vec<Document> = app
        .collection("machines")
        .find(doc! {"user_id":owner,"deletion_pending":{"$ne":true}})
        .projection(doc! {"name":1,"group_ids":1,"group_id":1,"private_owner_id":1,"private_owner_revoked":1,"enabled":1,"last_seen_at":1,"auth_required":1})
        .await?
        .try_collect()
        .await?;
    let groups: Vec<Document> = app
        .collection("machine_groups")
        .find(doc! {"user_id":owner})
        .projection(doc! {"name":1,"user_ids":1,"sort_order":1})
        .sort(doc! {"sort_order":1,"name":1})
        .await?
        .try_collect()
        .await?;
    let memberships: Vec<Document> = app
        .collection("workspace_members")
        .find(doc! {"workspace_id":owner})
        .projection(doc! {"user_id":1,"role":1})
        .await?
        .try_collect()
        .await?;
    let mut member_ids = vec![Bson::ObjectId(owner)];
    let mut roles = HashMap::from([(owner.to_hex(), "owner".to_owned())]);
    for membership in &memberships {
        if let Ok(id) = membership.get_object_id("user_id") {
            member_ids.push(Bson::ObjectId(id));
            roles.insert(id.to_hex(), store::string(membership, "role").to_owned());
        }
    }
    let users: Vec<Document> = app
        .collection("users")
        .find(doc! {"_id":{"$in":&member_ids}})
        .projection(doc! {"name":1,"username":1})
        .await?
        .try_collect()
        .await?;
    let books: Vec<Document> = app
        .collection("access_rulebooks")
        .find(doc! {"user_id":owner})
        .projection(doc! {"name":1,"user_id":1,"created_by":1,"group_id":1,"enabled":1,"rules":1,"revision":1,"created_at":1,"updated_at":1})
        .sort(doc! {"created_at":1})
        .await?
        .try_collect()
        .await?;
    let prefs = app
        .collection("private_networks")
        .find_one(doc! {"_id":owner.to_hex()})
        .await?
        .unwrap_or_default();
    let (network, suffix) = enrollment::preferences(&prefs)?;
    let mut peers: Vec<Document> = app
        .collection("private_peers")
        .find(doc! {"workspace_id":owner})
        .projection(doc! {"machine_id":1,"ip":1,"hostname":1,"created_at":1,"enabled":1,"credential_hash":1,"last_seen_at":1,"paths":1})
        .await?
        .try_collect()
        .await?;
    let peer_machines: Vec<_> = peers
        .iter()
        .filter_map(|p| p.get("machine_id").cloned())
        .collect();
    let names: Vec<Document> = app.collection("machines")
        .find(doc!{"$or":[{"user_id":owner},{"_id":{"$in":peer_machines}}],"deletion_pending":{"$ne":true}})
        .projection(doc!{"name":1,"aliases":1}).await?.try_collect().await?;
    let names_index: HashMap<_, _> = names
        .iter()
        .map(|m| {
            (
                store::id(m.get("_id")),
                inventory::default_field(m, "name", json!("")),
            )
        })
        .collect();
    let labels = private_names::assign(&names, &peers);
    peers.sort_by_key(|p| {
        labels
            .primary
            .get(&store::id(p.get("_id")))
            .cloned()
            .unwrap_or_default()
    });
    let now = DateTime::now();
    let private_peers: Vec<_> = peers.iter().map(|p| {
        let id = store::id(p.get("_id"));
        let mid = store::id(p.get("machine_id"));
        let mut paths: Vec<_> = p.get_document("paths").into_iter().flat_map(|d|d.values()).filter_map(Bson::as_str).collect();
        paths.sort_unstable(); paths.dedup();
        json!({"_id":id,"machine_id":mid,"machine_name":names_index.get(&mid),"ip":store::field(p,"ip"),
            "hostname":labels.primary.get(&id),"custom_hostname":!store::string(p,"hostname").is_empty(),
            "aliases":labels.aliases.get(&id).cloned().unwrap_or_default(),"enabled":inventory::default_field(p,"enabled",json!(true)),
            "installed":!store::string(p,"credential_hash").is_empty(),
            "online":p.get_datetime("last_seen_at").is_ok_and(|last| now.timestamp_millis().saturating_sub(last.timestamp_millis())<30_000),
            "last_seen_at":store::field(p,"last_seen_at"),"paths":paths})
    }).collect();
    let machines: Vec<_> = machines.iter().map(|m| json!({"_id":store::id(m.get("_id")),"name":inventory::default_field(m,"name",json!("")),
        "group_ids":inventory::group_ids(m).iter().map(|id|id.to_hex()).collect::<Vec<_>>(),
        "private_owner_id":m.get("private_owner_id").map(|v|store::id(Some(v))).filter(|v|!v.is_empty()).unwrap_or(owner.to_hex()),
        "private_owner_revoked":m.get_bool("private_owner_revoked").unwrap_or(false),"enabled":inventory::default_field(m,"enabled",json!(true)),
        "connection_status":inventory::status_at(&app,m,now)})).collect();
    let users: Vec<_> = users.iter().map(|u| json!({"_id":store::id(u.get("_id")),"name":inventory::default_field(u,"name",json!("")),
        "email":inventory::default_field(u,"username",json!("")),"role":roles.get(&store::id(u.get("_id")))})).collect();
    let allowed: HashSet<_> = member_ids.iter().map(|v| store::id(Some(v))).collect();
    let groups: Vec<_> = groups.iter().map(|g| json!({"_id":store::id(g.get("_id")),"name":inventory::default_field(g,"name",json!("")),
        "user_ids":g.get_array("user_ids").into_iter().flatten().map(|v|store::id(Some(v))).filter(|id|allowed.contains(id)).collect::<Vec<_>>()})).collect();
    let invitations: Vec<Document> = if role == "owner" || role == "admin" {
        app.collection("workspace_invites").find(doc!{"user_id":owner,"consumed_at":Bson::Null,"revoked_at":Bson::Null,"expires_at":{"$gt":now}})
            .projection(doc!{"email":1,"role":1,"expires_at":1}).await?.try_collect().await?
    } else {
        Vec::new()
    };
    Ok(Json(
        json!({"workspace_id":owner.to_hex(),"role":role,"transport_ready":false,
        "network":{"cidr":network.cidr(),"dns_suffix":suffix},"machines":machines,"users":users,"groups":groups,
        "books":books.iter().map(store::document).collect::<Vec<_>>(),"private_peers":private_peers,
        "invitations":invitations.iter().map(store::document).collect::<Vec<_>>()}),
    ))
}
