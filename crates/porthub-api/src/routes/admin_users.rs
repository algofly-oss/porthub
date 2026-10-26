//! Platform-only account provisioning and explicit, durable account retirement.
use crate::{
    auth,
    domain::{accounts, workspaces},
    error::{ApiError, ApiResult},
    input::{ApiBody, Model},
    store, App,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, post},
    Json, Router,
};
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use serde_json::{json, Value};
use std::sync::Arc;

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/admin/users", post(create))
        .route("/api/admin/users/{id}", delete(remove))
}
async fn admin(app: &App, headers: &HeaderMap) -> ApiResult<mongodb::bson::Document> {
    let user = auth::current_user(app, headers).await?;
    if store::string(&user, "role") != "admin" {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Admin access required",
        ));
    }
    Ok(user)
}
async fn create(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(raw): ApiBody,
) -> ApiResult<(StatusCode, Json<Value>)> {
    admin(&app, &headers).await?;
    let mut model = Model::new(raw)?;
    let name = model.required_string("name").trim().to_owned();
    let email = model.required_string("email").trim().to_lowercase();
    let password = model.required_string("password");
    model.string_length("name", &name, 1, Some(100));
    model.string_length("email", &email, 3, Some(254));
    if !regex::Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
        .expect("email expression")
        .is_match(&email)
    {
        model.add("email", "Enter a valid email address", "value_error");
    }
    if !(8..=72).contains(&password.len()) {
        model.add(
            "password",
            "Use a password between 8 and 72 bytes",
            "value_error",
        );
    }
    model.finish()?;
    let mut record = accounts::hash_password(password).await?;
    let _guard = app.connection_lock.lock().await;
    // Recheck after waiting for another operation; never use stale admin authority.
    admin(&app, &headers).await?;
    if app
        .collection("users")
        .find_one(doc! {"username":{"$regex":format!("^{}$",regex::escape(&email)),"$options":"i"}})
        .await?
        .is_some()
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "An account with this email already exists",
        ));
    }
    accounts::ensure_unique_usernames(&app).await?;
    let id = ObjectId::new();
    record.extend(doc!{"_id":id,"name":&name,"username":&email,"email":&email,"role":"user","created_at":DateTime::now()});
    app.collection("users")
        .insert_one(record)
        .await
        .map_err(|error| {
            if store::duplicate(&error) {
                ApiError::new(
                    StatusCode::CONFLICT,
                    "An account with this email already exists",
                )
            } else {
                error.into()
            }
        })?;
    // No session or Set-Cookie is created for the new account. The caller stays admin.
    Ok((
        StatusCode::CREATED,
        Json(
            json!({"msg":"Account created","data":{"id":id.to_hex(),"name":name,"email":email,"role":"user"}}),
        ),
    ))
}
async fn remove(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    admin(&app, &headers).await?;
    let id = workspaces::object_id(&id, "Invalid account ID")?;
    let mut model = Model::new(raw)?;
    let confirmation = model.required_string("confirm_email");
    model.finish()?;
    let work = app.clone();
    tokio::spawn(async move {
        let _lifecycle = work.account_lifecycle.write().await;
        let actor = admin(&work, &headers).await?;
        if actor.get_object_id("_id").ok() == Some(id) {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "Use account settings to delete your own account",
            ));
        }
        let _connections = work.connection_lock.lock().await;
        let _networks = work.private_network_lock.lock().await;
        let user = work
            .collection("users")
            .find_one(doc! {"_id":id})
            .await?
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Account not found"))?;
        let email = store::string(&user, "email");
        let email = if email.is_empty() {
            store::string(&user, "username")
        } else {
            email
        };
        if confirmation.trim().to_lowercase() != email.trim().to_lowercase() {
            return Err(ApiError::bad_request(
                "Type the account email to confirm deletion",
            ));
        }
        crate::account_delete::delete_locked(&work, id).await?;
        Ok(Json(json!({"msg":"Account and related resources deleted"})))
    })
    .await
    .map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Account deletion task interrupted; pending cleanup will resume",
        )
    })?
}
