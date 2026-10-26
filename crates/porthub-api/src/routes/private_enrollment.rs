use crate::{
    domain::{
        enrollment::preferences,
        machine_client::View,
        private_enrollment as enrollment, private_names,
        workspaces::{object_id, token_digest},
    },
    enrollment_ticket,
    error::{ApiError, ApiResult},
    input::ApiBody,
    routes::access::{browser, WorkspaceQuery},
    store, App,
};
use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{post, put},
    Json, Router,
};
use mongodb::{
    bson::{doc, Bson, DateTime},
    options::ReturnDocument,
};
use rand::{distributions::Alphanumeric, Rng};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc};
pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/access/private/peers", post(enroll))
        .route("/api/access/private/bootstrap", post(bootstrap))
        .route("/api/access/private/peers/{id}/hostname", put(rename))
}
fn conflict(message: &str) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, message)
}
async fn enroll(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let (mid, name) = enrollment::parse(raw)?;
    let (user, owner, role) =
        browser(&app, &headers, &Method::POST, &query.workspace, false).await?;
    let mid = object_id(&mid, "Invalid machine")?;
    let _guard = app.connection_lock.lock().await;
    let _network_guard = app.private_network_lock.lock().await;
    let machine = app
        .collection("machines")
        .find_one(doc! {"_id":mid,"deletion_pending":{"$ne":true}})
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::FORBIDDEN, "You cannot enroll this machine"))?;
    if machine.get("user_id") != user.get("_id")
        && !(matches!(role.as_str(), "owner" | "admin")
            && machine.get_object_id("user_id").ok() == Some(owner))
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "You cannot enroll this machine",
        ));
    }
    if machine.get_bool("enabled") == Ok(false) {
        return Err(conflict(
            "Enable the machine before enrolling private access",
        ));
    }
    if machine.get_bool("private_owner_revoked") == Ok(true)
        || machine.contains_key("native_deletion")
    {
        return Err(conflict(
            "Private ownership is revoked or machine deletion is in progress",
        ));
    }
    enrollment::initialize(&app).await?;
    let id = format!("{owner}:{mid}");
    let existing = app
        .collection("private_peers")
        .find_one(doc! {"_id":&id})
        .await?;
    if existing
        .as_ref()
        .is_some_and(|p| p.contains_key("credential_hash"))
    {
        return Err(conflict(
            "This machine already has a private client; revoke it before reinstalling",
        ));
    }
    let prefs = crate::domain::private_networks::ensure_locked(&app, &owner.to_hex()).await?;
    let (network, suffix) = preferences(&prefs)?;
    if let Some(name) = &name {
        enrollment::check_name(&app, owner, &Bson::ObjectId(mid), name).await?;
    }
    let generation = enrollment::token()?;
    let now = DateTime::now();
    let mut address = String::new();
    let mut saved = false;
    for _ in 0..8 {
        let (_, peers) = enrollment::names(&app, owner).await?;
        address = if let Some(existing) = &existing {
            store::string(existing, "ip").into()
        } else {
            network.allocate(&mid.to_hex(), &enrollment::occupied(&peers))?
        };
        let mut set = doc! {"workspace_id":owner,"machine_id":mid,"owner_id":machine.get("user_id"),"ip":&address,"enabled":true,"updated_at":now,"enrollment_generation":&generation};
        if let Some(name) = &name {
            set.insert("hostname", name);
        }
        let result = app
            .collection("private_peers")
            .update_one(
                doc! {"_id":&id,"credential_hash":{"$exists":false}},
                doc! {"$set":set,"$setOnInsert":{"created_at":now,"revision":0_i64}},
            )
            .upsert(true)
            .await;
        match result {
            Ok(_) => {
                saved = true;
                break;
            }
            Err(error) if store::duplicate(&error) => {
                if app
                    .collection("private_peers")
                    .find_one(doc! {"_id":&id,"credential_hash":{"$exists":true}})
                    .await?
                    .is_some()
                {
                    return Err(conflict("Enrollment was already completed"));
                }
                if let Some(name) = &name {
                    enrollment::check_name(&app, owner, &Bson::ObjectId(mid), name).await?;
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    if !saved {
        return Err(conflict("Address allocation changed; retry enrollment"));
    }
    let ticket = enrollment::token()?;
    let expires = DateTime::from_millis(now.timestamp_millis() + 600_000);
    app.collection("private_install_tickets")
        .update_many(
            doc! {"peer_id":&id,"consumed_at":Bson::Null},
            doc! {"$set":{"consumed_at":now}},
        )
        .await?;
    app.collection("private_install_tickets").insert_one(doc!{"_id":token_digest(&ticket),"peer_id":&id,"created_by":user.get("_id"),"generation":&generation,"consumed_at":Bson::Null,"expires_at":expires}).await?;
    let short: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    app.collection("machine_install_tickets").insert_one(doc!{"_id":token_digest(&short),"kind":"private","machine_id":mid,"token_digest":token_digest(store::string(&machine,"token")),"private_ticket":&ticket,"expires_at":expires}).await?;
    let empty = HashMap::new();
    let view = View {
        headers: &headers,
        query: &empty,
    };
    let uri = enrollment_ticket::link(&view.public_base(&app, &machine), &short)?;
    let (machines, peers) = enrollment::names(&app, owner).await?;
    let names = private_names::assign(&machines, &peers);
    Ok(Json(
        json!({"peer_id":id,"ip":address,"hostname":format!("{}.{suffix}",names.primary[&id]),"ticket":ticket,"expires_in":600,
        "command":format!("curl -fsSL {} | bash",enrollment_ticket::shell_quote(&uri)),"native_command":format!("porthub enroll --ticket {}",enrollment_ticket::shell_quote(&uri))}),
    ))
}
async fn bootstrap(State(app): State<Arc<App>>, ApiBody(raw): ApiBody) -> ApiResult<Response> {
    let ticket = enrollment::parse_ticket(raw)?;
    let (claim, peer) = enrollment::resolve(&app, &ticket).await?;
    let now = DateTime::now();
    let claimed = app
        .collection("private_install_tickets")
        .find_one_and_update(
            doc! {"_id":claim.get("_id"),"consumed_at":Bson::Null,"expires_at":{"$gt":now}},
            doc! {"$set":{"consumed_at":now}},
        )
        .return_document(ReturnDocument::After)
        .await?;
    if claimed.is_none() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Installer ticket is invalid, expired or already used",
        ));
    }
    let credential = enrollment::token()?;
    let generation = peer.get("enrollment_generation").cloned();
    let mut filter =
        doc! {"_id":peer.get("_id"),"enabled":true,"credential_hash":{"$exists":false}};
    if let Some(generation) = generation {
        filter.insert("enrollment_generation", generation);
    } else {
        filter.insert("enrollment_generation", doc! {"$exists":false});
    }
    let result = app
        .collection("private_peers")
        .update_one(
            filter,
            doc! {"$set":{"credential_hash":token_digest(&credential),"credential_created_at":now}},
        )
        .await?;
    if result.modified_count != 1 {
        return Err(conflict("Enrollment was already completed or superseded"));
    }
    Ok(([(header::CACHE_CONTROL,"no-store"),(header::REFERRER_POLICY,"no-referrer")],Json(json!({"peer_id":store::field(&peer,"_id"),"token":credential,"workspace":store::field(&peer,"workspace_id")}))).into_response())
}
async fn rename(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>,
    Path(id): Path<String>,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let name = enrollment::parse_hostname(raw)?;
    let (user, owner, role) =
        browser(&app, &headers, &Method::PUT, &query.workspace, false).await?;
    let _guard = app.connection_lock.lock().await;
    let mut filter = doc! {"_id":&id,"workspace_id":owner};
    if !matches!(role.as_str(), "owner" | "admin") {
        filter.insert("owner_id", user.get("_id").cloned().unwrap_or_default());
    }
    let peer = app
        .collection("private_peers")
        .find_one(filter.clone())
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Private peer not found"))?;
    enrollment::initialize(&app).await?;
    let mut change = doc! {"$set":{"updated_at":DateTime::now()}};
    if let Some(name) = name {
        enrollment::check_name(
            &app,
            owner,
            peer.get("machine_id").unwrap_or(&Bson::Null),
            &name,
        )
        .await?;
        change
            .get_document_mut("$set")
            .unwrap()
            .insert("hostname", name);
    } else {
        change.insert("$unset", doc! {"hostname":""});
    }
    if let Err(error) = app
        .collection("private_peers")
        .update_one(filter, change)
        .await
    {
        if store::duplicate(&error) {
            return Err(conflict("This private hostname is already in use"));
        }
        return Err(error.into());
    }
    let (machines, peers) = enrollment::names(&app, owner).await?;
    let names = private_names::assign(&machines, &peers);
    Ok(Json(json!({"hostname":names.primary[&id]})))
}
