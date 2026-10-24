use crate::{
    auth,
    domain::workspaces,
    error::{ApiError, ApiResult},
    input::{ApiBody, Model},
    store, App,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    routing::{delete, get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime, Document};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc};

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/access/workspaces", get(list_workspaces))
        .route("/api/access/invitations", post(invite))
        .route("/api/access/invitations/{id}", delete(revoke_invite))
        .route("/api/access/invitations/preview", post(preview_invite))
        .route("/api/access/invitations/accept", post(accept_invite))
        .route("/api/access/members/{id}", delete(remove_member))
}

#[derive(Deserialize, Default)]
pub struct WorkspaceQuery {
    #[serde(default)]
    pub workspace: String,
}

pub fn check_origin(headers: &HeaderMap, method: &Method) -> ApiResult<()> {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return Ok(());
    }
    if let Some(origin) = headers.get("origin") {
        let same = origin
            .to_str()
            .ok()
            .and_then(|origin| origin.parse::<Uri>().ok())
            .filter(|uri| matches!(uri.scheme_str(), Some("http" | "https")))
            .and_then(|uri| {
                uri.authority()
                    .map(|authority| authority.as_str().to_owned())
            })
            .zip(headers.get("host").and_then(|host| host.to_str().ok()))
            .is_some_and(|(origin, host)| origin.eq_ignore_ascii_case(host));
        if !same {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "Cross-origin workspace changes are not allowed",
            ));
        }
    }
    Ok(())
}

pub async fn browser(
    app: &App,
    headers: &HeaderMap,
    method: &Method,
    workspace: &str,
    manage: bool,
) -> ApiResult<(Document, ObjectId, String)> {
    check_origin(headers, method)?;
    let user = auth::current_user(app, headers).await?;
    let (owner, role) = workspaces::access(app, &user, workspace, manage).await?;
    Ok((user, owner, role))
}

async fn list_workspaces(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let user = auth::current_user(&app, &headers).await?;
    let user_id = user
        .get_object_id("_id")
        .map_err(|_| ApiError::unauthenticated())?;
    let memberships: Vec<Document> = app
        .collection("workspace_members")
        .find(doc! {"user_id":user_id})
        .await?
        .try_collect()
        .await?;
    let mut ids = vec![Bson::ObjectId(user_id)];
    let mut roles = HashMap::new();
    for membership in memberships {
        if let Some(id) = membership.get("workspace_id") {
            ids.push(id.clone());
            roles.insert(
                store::id(Some(id)),
                store::string(&membership, "role").to_owned(),
            );
        }
    }
    roles.insert(user_id.to_hex(), "owner".into());
    let owners: Vec<Document> = app
        .collection("users")
        .find(doc! {"_id":{"$in":ids}})
        .await?
        .try_collect()
        .await?;
    let values:Vec<Value> = owners.iter().map(|owner| {
        let id = store::id(owner.get("_id"));
        let name = store::string(owner,"name");
        let name = if name.is_empty() {store::string(owner,"username")} else {name};
        json!({"id":id,"name":format!("{name}'s Workspace"),"role":roles.get(&id).cloned().unwrap_or_default()})
    }).collect();
    Ok(Json(json!({"data":values})))
}

fn invitation_token(raw: Value) -> ApiResult<String> {
    let mut model = Model::new(raw)?;
    let token = model.required_string("token");
    model.string_length("token", &token, 32, Some(200));
    model.finish()?;
    Ok(token)
}

async fn invite(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let mut model = Model::new(raw)?;
    let email = model.required_string("email");
    model.string_length("email", &email, 3, Some(254));
    let email = email.trim().to_lowercase();
    if model.field_valid("email")
        && (email.matches('@').count() != 1
            || email.chars().any(char::is_whitespace)
            || !email.rsplit('@').next().unwrap_or("").contains('.'))
    {
        model.add("email", "Enter a valid email address", "value_error");
    }
    let role = model.literal("role", "member", &["admin", "member"]);
    model.finish()?;
    let (user, owner, issuer_role) =
        browser(&app, &headers, &Method::POST, &query.workspace, true).await?;
    if role == "admin" && issuer_role != "owner" {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Only the owner can invite administrators",
        ));
    }
    let count = app.collection("workspace_invites").count_documents(doc! {"user_id":owner,"consumed_at":Bson::Null,"revoked_at":Bson::Null,"expires_at":{"$gt":DateTime::now()}}).await?;
    if count >= 100 {
        return Err(ApiError::bad_request(
            "Revoke an outstanding invitation before creating more",
        ));
    }
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut bytes).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not generate invitation",
        )
    })?;
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let now = DateTime::now();
    let expires = DateTime::from_millis(now.timestamp_millis() + 7 * 24 * 60 * 60 * 1000);
    app.collection("workspace_invites").insert_one(doc! {"_id":workspaces::token_digest(&token),"user_id":owner,"email":email,"role":role,
        "created_by":user.get("_id"),"created_at":now,"expires_at":expires,"consumed_at":Bson::Null,"revoked_at":Bson::Null}).await?;
    Ok(Json(
        json!({"token":token,"expires_at":store::datetime(expires.timestamp_millis())}),
    ))
}

async fn revoke_invite(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let (_, owner, _) = browser(&app, &headers, &Method::DELETE, &query.workspace, true).await?;
    app.collection("workspace_invites")
        .update_one(
            doc! {"_id":id,"user_id":owner,"consumed_at":Bson::Null},
            doc! {"$set":{"revoked_at":DateTime::now()}},
        )
        .await?;
    Ok(Json(json!({"msg":"Invitation revoked"})))
}

async fn preview_invite(
    State(app): State<Arc<App>>,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let invite = workspaces::valid_invitation(&app, &invitation_token(raw)?).await?;
    let owner = app
        .collection("users")
        .find_one(doc! {"_id":invite.get("user_id")})
        .await?;
    let workspace = owner
        .as_ref()
        .and_then(|owner| owner.get("name"))
        .map(store::json)
        .unwrap_or(json!("PortHub"));
    Ok(Json(
        json!({"email":store::field(&invite,"email"),"role":store::field(&invite,"role"),"workspace":workspace,"expires_at":store::field(&invite,"expires_at")}),
    ))
}

async fn accept_invite(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let token = invitation_token(raw)?;
    check_origin(&headers, &Method::POST)?;
    let user = auth::current_user(&app, &headers).await?;
    Ok(Json(
        json!({"workspace_id":workspaces::accept_invitation(&app,&user,&token).await?}),
    ))
}

async fn remove_member(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let (user, owner, role) =
        browser(&app, &headers, &Method::DELETE, &query.workspace, true).await?;
    let target = workspaces::object_id(&id, "Invalid member")?;
    if target == owner {
        return Err(ApiError::bad_request(
            "The workspace owner cannot be removed",
        ));
    }
    let key = format!("{}:{}", owner.to_hex(), target.to_hex());
    let membership = app
        .collection("workspace_members")
        .find_one(doc! {"_id":&key})
        .await?;
    if membership
        .as_ref()
        .is_some_and(|member| store::string(member, "role") == "admin")
        && role != "owner"
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Only the owner can remove administrators",
        ));
    }
    if user.get_object_id("_id").ok() == Some(target) {
        return Err(ApiError::bad_request(
            "Ask the workspace owner to remove your administrative membership",
        ));
    }
    app.collection("workspace_members")
        .delete_one(doc! {"_id":key})
        .await?;
    app.collection("machines")
        .update_many(
            doc! {"user_id":owner,"private_owner_id":target},
            doc! {"$set":{"private_owner_revoked":true}},
        )
        .await?;
    app.collection("machine_groups")
        .update_many(doc! {"user_id":owner}, doc! {"$pull":{"user_ids":target}})
        .await?;
    app.collection("workspace_invites")
        .update_many(
            doc! {"user_id":owner,"created_by":target,"consumed_at":Bson::Null},
            doc! {"$set":{"revoked_at":DateTime::now()}},
        )
        .await?;
    Ok(Json(json!({"msg":"Member removed"})))
}
