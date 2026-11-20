//! Agentless LAN targets have independent private peer identities. The parent
//! receives their delegated credentials only through its authenticated sync.
use super::access::{WorkspaceQuery, browser};
use crate::{
    App,
    domain::{
        enrollment::preferences,
        private_enrollment as enrollment, private_networks,
        workspaces::{object_id, token_digest},
    },
    error::{ApiError, ApiResult},
    input::ApiBody,
    store,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode},
    routing::{delete, get},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::TryStreamExt;
use mongodb::bson::{Bson, DateTime, Document, doc, oid::ObjectId};
use serde_json::{Value, json};
use std::{net::Ipv4Addr, sync::Arc};

const LIMIT: i64 = 64;
pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route(
            "/api/machines/{parent}/virtual-hosts",
            get(list).post(create),
        )
        .route("/api/machines/{parent}/virtual-hosts/{id}", delete(remove))
}
fn missing() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "Virtual host or provider not found")
}
fn conflict(message: &str) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, message)
}

async fn provider(app: &App, owner: ObjectId, id: ObjectId) -> ApiResult<Document> {
    let mut machine=app.collection("machines").find_one(doc!{"_id":id,"user_id":owner,"kind":{"$ne":"virtual_host"},"deletion_pending":{"$ne":true}}).await?.ok_or_else(missing)?;
    let private = app
        .collection("private_peers")
        .find_one(doc! {"_id":format!("{owner}:{id}"),"enabled":true})
        .projection(doc! {"virtual_host_provider":1,"last_seen_at":1})
        .await?;
    let (online, supported) = crate::domain::inventory::provider_health(&machine, private.as_ref());
    machine.insert("provider_online", online);
    machine.insert("provider_capable", supported);
    Ok(machine)
}
fn view(peer: &Document, provider: &Document, suffix: &str) -> Value {
    let name = store::string(peer, "hostname");
    json!({"id":store::id(peer.get("machine_id")),"peer_id":store::id(peer.get("_id")),"kind":"virtual_host","name":name,"target_ip":store::string(peer,"target_ip"),
        "private_ip":store::string(peer,"ip"),"hostname":format!("{name}.{suffix}"),"via":{"id":store::id(provider.get("_id")),"name":store::string(provider,"name"),"online":provider.get_bool("provider_online").unwrap_or(false),"supports_virtual_hosts":provider.get_bool("provider_capable").unwrap_or(false)}})
}
async fn list(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>,
    Path(parent): Path<String>,
) -> ApiResult<Json<Value>> {
    let (_, owner, _) = browser(&app, &headers, &Method::GET, &query.workspace, true).await?;
    let id = object_id(&parent, "Invalid provider")?;
    let parent = provider(&app, owner, id).await?;
    let prefs = app
        .collection("private_networks")
        .find_one(doc! {"_id":owner.to_hex()})
        .await?
        .unwrap_or_default();
    let (_, suffix) = preferences(&prefs)?;
    let peers: Vec<Document> = app
        .collection("private_peers")
        .find(doc! {"workspace_id":owner,"virtual_parent":id,"virtual_published":true})
        .sort(doc! {"hostname":1})
        .limit(LIMIT)
        .await?
        .try_collect()
        .await?;
    Ok(Json(
        json!({"provider_online":parent.get_bool("provider_online").unwrap_or(false),"provider_supported":parent.get_bool("provider_capable").unwrap_or(false),"virtual_hosts":peers.iter().map(|p|view(p,&parent,&suffix)).collect::<Vec<_>>()}),
    ))
}
async fn create(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>,
    Path(parent): Path<String>,
    ApiBody(body): ApiBody,
) -> ApiResult<Json<Value>> {
    let (_, owner, _) = browser(&app, &headers, &Method::POST, &query.workspace, true).await?;
    let id = object_id(&parent, "Invalid provider")?;
    let name = enrollment::parse_hostname(json!({"hostname":body["name"]}))?
        .ok_or_else(|| ApiError::bad_request("Private hostname required"))?;
    let target: Ipv4Addr = body["target_ip"]
        .as_str()
        .and_then(|v| v.parse().ok())
        .filter(Ipv4Addr::is_private)
        .ok_or_else(|| ApiError::bad_request("A private LAN IPv4 address is required"))?;
    let _connection = app.connection_lock.lock().await;
    let _allocation = app.private_network_lock.lock().await;
    #[cfg(feature = "private-sparse")]
    let _stable = crate::private_renumber::fence::stable_with_allocation(&app, owner).await?;
    let parent = provider(&app, owner, id).await?;
    let parent_peer=app.collection("private_peers").find_one(doc!{"_id":format!("{owner}:{id}"),"enabled":true,"credential_hash":{"$type":"string"}}).await?.ok_or_else(||conflict("Enroll the provider in private networking first"))?;
    if parent.get_bool("enabled") == Ok(false)
        || parent.get_bool("private_owner_revoked") == Ok(true)
    {
        return Err(conflict("The provider is disabled"));
    }
    let prefs = private_networks::ensure_locked(&app, &owner.to_hex()).await?;
    if private_networks::pools(&prefs)?
        .iter()
        .any(|pool| pool.contains(target))
    {
        return Err(ApiError::bad_request(
            "The target must be outside the PortHub address pools",
        ));
    }
    let (_, suffix) = preferences(&prefs)?;
    enrollment::initialize(&app).await?;
    let machine = ObjectId::new();
    let via = doc! {"id":id.to_hex(),"name":store::string(&parent,"name")};
    let peers = app.collection("private_peers");
    let existing = peers
        .find_one(doc! {"workspace_id":owner,"virtual_parent":id,"hostname":&name})
        .await?;
    if let Some(ref p) = existing {
        if p.get_bool("virtual_deleting") == Ok(true) {
            return Err(conflict("Virtual host removal is in progress"));
        }
        if store::string(p, "target_ip") != target.to_string() {
            return Err(conflict("Name is already used for a different target"));
        }
        if p.get_bool("virtual_published") == Ok(true) {
            return Ok(Json(json!({"virtual_host":view(p,&parent,&suffix)})));
        }
    }
    let child = if let Some(peer) = existing {
        peer
    } else {
        let rows: Vec<Document> = peers
            .find(doc! {"workspace_id":owner,"virtual_parent":id})
            .projection(doc! {"virtual_slot":1})
            .limit(LIMIT)
            .await?
            .try_collect()
            .await?;
        let slot = (0..LIMIT)
            .find(|slot| {
                rows.iter()
                    .all(|row| row.get_i64("virtual_slot") != Ok(*slot))
            })
            .ok_or_else(|| conflict("Virtual host capacity reached"))?;
        enrollment::check_name(&app, owner, &Bson::ObjectId(machine), &name).await?;
        let (_, assigned) = enrollment::names(&app, owner).await?;
        let ip = private_networks::allocate_locked(
            &app,
            &owner.to_hex(),
            &machine.to_hex(),
            &enrollment::occupied(&assigned),
        )
        .await?;
        let mut peer = doc! {"_id":format!("{owner}:{machine}"),"workspace_id":owner,"owner_id":owner,"machine_id":machine,"hostname":&name,"ip":ip,"virtual_slot":slot,"via":&via,"kind":"virtual_host","enabled":true,"virtual_parent":id,"virtual_published":false,"target_ip":target.to_string(),"enrollment_generation":enrollment::token()?,"parent_generation":parent_peer.get("enrollment_generation"),"revision":0_i64,"created_at":DateTime::now()};
        #[cfg(feature = "private-sparse")]
        peer.insert(
            "address_generation",
            crate::private_renumber::native_repair::published_generation(&app, owner, &prefs)
                .await?,
        );
        peers.insert_one(&peer).await.map_err(|e| {
            if store::duplicate(&e) {
                conflict("Concurrent private allocation; retry creation")
            } else {
                e.into()
            }
        })?;
        peer
    };
    let mid = child.get_object_id("machine_id").map_err(|_| missing())?;
    let machine = doc! {"user_id":owner,"name":&name,"kind":"virtual_host","virtual_parent":id,"via":via,"target_ip":target.to_string(),"enabled":true,"created_at":DateTime::now()};
    app.collection("machines")
        .update_one(
            doc! {"_id":mid,"kind":"virtual_host","virtual_parent":id},
            doc! {"$setOnInsert":machine},
        )
        .upsert(true)
        .await?;
    let published = peers
        .update_one(
            doc! {"_id":child.get("_id"),"virtual_parent":id,"virtual_deleting":{"$ne":true},"enabled":true},
            doc! {"$set":{"virtual_published":true}},
        )
        .await?;
    if published.matched_count == 0 {
        app.collection("machines")
            .delete_one(doc! {"_id":mid,"kind":"virtual_host","virtual_parent":id,"user_id":owner})
            .await?;
        return Err(conflict("Virtual host removal is in progress"));
    }
    app.private_changes.changed(owner);
    Ok(Json(json!({"virtual_host":view(&child,&parent,&suffix)})))
}
async fn remove(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>,
    Path((parent, child)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let (_, owner, _) = browser(&app, &headers, &Method::DELETE, &query.workspace, true).await?;
    let parent = object_id(&parent, "Invalid provider")?;
    let child = object_id(&child, "Invalid virtual host")?;
    let _connection = app.connection_lock.lock().await;
    let _allocation = app.private_network_lock.lock().await;
    #[cfg(feature = "private-sparse")]
    let _stable = crate::private_renumber::fence::revocation(&app, owner).await?;
    delete_child(&app, owner, parent, child).await?;
    app.private_changes.changed(owner);
    Ok(Json(json!({"removed":true})))
}

async fn delete_child(
    app: &App,
    owner: ObjectId,
    parent: ObjectId,
    child: ObjectId,
) -> ApiResult<()> {
    let id = format!("{owner}:{child}");
    let filter = doc! {"_id":&id,"workspace_id":owner,"virtual_parent":parent};
    let changed=app.collection("private_peers").update_one(filter.clone(),doc!{"$set":{"enabled":false,"virtual_published":false,"virtual_deleting":true},"$unset":{"credential_hash":""}}).await?;
    if changed.matched_count == 0 {
        return Err(missing());
    }
    app.private_relay
        .retire_identities(std::slice::from_ref(&id));
    app.collection("private_signals")
        .delete_many(doc! {"$or":[{"from":&id},{"to":&id}]})
        .await?;
    app.collection("machines")
        .delete_one(
            doc! {"_id":child,"kind":"virtual_host","virtual_parent":parent,"user_id":owner},
        )
        .await?;
    app.collection("private_peers").delete_one(filter).await?;
    Ok(())
}

pub(crate) async fn delete_children(app: &App, owner: ObjectId, parent: ObjectId) -> ApiResult<()> {
    let rows: Vec<Document> = app
        .collection("private_peers")
        .find(doc! {"workspace_id":owner,"virtual_parent":parent})
        .projection(doc! {"machine_id":1})
        .await?
        .try_collect()
        .await?;
    for row in rows {
        delete_child(
            app,
            owner,
            parent,
            row.get_object_id("machine_id").map_err(|_| missing())?,
        )
        .await?;
    }
    Ok(())
}
pub(crate) async fn retire_with_children(app: &App, owner: ObjectId, peer: &str) -> ApiResult<()> {
    let mut ids = vec![peer.to_owned()];
    if let Some((_, mid)) = peer.split_once(':') {
        if let Ok(mid) = ObjectId::parse_str(mid) {
            let mut rows = app
                .collection("private_peers")
                .find(doc! {"workspace_id":owner,"virtual_parent":mid})
                .projection(doc! {"_id":1})
                .await?;
            while let Some(row) = rows.try_next().await? {
                ids.push(store::string(&row, "_id").to_owned());
            }
        }
    }
    app.private_relay.retire_identities(&ids);
    Ok(())
}
// Check the current parent enrollment on every authorization path. Binding the
// child to the parent's credential hash invalidates it across token rotation.
pub(crate) async fn parent_valid(app: &App, peer: &Document) -> ApiResult<bool> {
    let Ok(id) = peer.get_object_id("virtual_parent") else {
        return Ok(!peer.contains_key("virtual_parent"));
    };
    let Ok(owner) = peer.get_object_id("workspace_id") else {
        return Ok(false);
    };
    let Ok(hash) = peer.get_str("parent_hash") else {
        return Ok(false);
    };
    if peer.get_bool("virtual_published") != Ok(true) {
        return Ok(false);
    }
    let alive=app.collection("private_peers").find_one(doc!{"_id":format!("{owner}:{id}"),"enabled":true,"credential_hash":hash,"enrollment_generation":peer.get("parent_generation"),"virtual_parent":{"$exists":false},"virtual_host_provider":true,"last_seen_at":{"$gt":DateTime::from_millis(DateTime::now().timestamp_millis()-30_000)}}).projection(doc!{"_id":1}).await?.is_some();
    if !alive {
        return Ok(false);
    }
    Ok(app.collection("machines").find_one(doc!{"_id":id,"user_id":owner,"enabled":{"$ne":false},"deletion_pending":{"$ne":true},"private_owner_revoked":{"$ne":true},"kind":{"$ne":"virtual_host"}}).projection(doc!{"_id":1}).await?.is_some())
}
pub(crate) async fn assignments(
    app: &App,
    parent: &Document,
    token: &str,
) -> ApiResult<Vec<Value>> {
    let owner = parent
        .get_object_id("workspace_id")
        .map_err(|_| missing())?;
    let id = parent.get_object_id("machine_id").map_err(|_| missing())?;
    let filter =
        doc! {"workspace_id":owner,"virtual_parent":id,"virtual_published":true,"enabled":true};
    let children: Vec<Document> = app
        .collection("private_peers")
        .find(filter)
        .sort(doc! {"_id":1})
        .limit(LIMIT)
        .await?
        .try_collect()
        .await?;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, token.as_bytes());
    let mut result = Vec::new();
    for child in children {
        let cid = store::string(&child, "_id");
        let generation = child
            .get_str("enrollment_generation")
            .map_err(|_| missing())?;
        let data = format!("porthub-virtual-host-v1\0{cid}\0{generation}");
        let token = URL_SAFE_NO_PAD.encode(ring::hmac::sign(&key, data.as_bytes()).as_ref());
        let hash = token_digest(&token);
        if child.get_str("credential_hash") != Ok(hash.as_str())
            || child.get("parent_generation") != parent.get("enrollment_generation")
        {
            // A re-enrolled provider keeps its virtual addresses. Bind only an
            // authenticated current enrollment, and fence concurrent rotations.
            let peers = app.collection("private_peers");
            let current = doc! {"_id":parent.get("_id"),"enabled":true,
            "credential_hash":parent.get("credential_hash"),"enrollment_generation":parent.get("enrollment_generation")};
            if peers
                .find_one(current)
                .projection(doc! {"_id":1})
                .await?
                .is_none()
            {
                return Err(ApiError::new(
                    StatusCode::FORBIDDEN,
                    "Provider enrollment changed",
                ));
            }
            let previous = doc! {"_id":cid,"enrollment_generation":generation,"enabled":true,
            "virtual_published":true,"credential_hash":child.get("credential_hash"),
            "parent_generation":child.get("parent_generation")};
            let binding = doc! {"credential_hash":hash,"parent_hash":parent.get("credential_hash"),
            "parent_generation":parent.get("enrollment_generation")};
            let updated = peers.update_one(previous, doc! {"$set":binding}).await?;
            if updated.matched_count != 1 {
                continue;
            }
        }
        result.push(
            json!({"peer_id":cid,"target_ip":store::string(&child,"target_ip"),"token":token}),
        );
    }
    Ok(result)
}
