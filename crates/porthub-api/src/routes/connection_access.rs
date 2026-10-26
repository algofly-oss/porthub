//! Owner-managed HTTP access locks. Verifiers never enter inventory responses.
use crate::{auth, error::{ApiError, ApiResult}, generated, input::Model, store, App};
use axum::{extract::{Path, State}, http::{HeaderMap, StatusCode}, routing::put, Json, Router};
use mongodb::bson::{doc, DateTime};
use serde_json::{json, Value};
use std::sync::Arc;

pub fn router() -> Router<Arc<App>> {
    Router::new().route("/api/connections/access/{id}", put(update))
}

async fn update(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let user = auth::current_user(&app, &headers).await?;
    let owner = user.get("_id").cloned().ok_or_else(ApiError::unauthenticated)?;
    let mut model = Model::new(body)?;
    let mode = model.required_string("mode");
    let secret = model.optional_string("secret").filter(|value| !value.is_empty());
    model.finish()?;
    if !matches!(mode.as_str(), "off" | "pin" | "key") { return Err(ApiError::bad_request("Access mode must be off, pin, or key")); }
    // Authorize before performing an expensive hash.
    super::connections::owned(&app, &owner, &id, StatusCode::NOT_FOUND).await?;
    let verifier = if mode != "off" {
        if let Some(secret) = secret {
            if (mode == "pin" && (secret.len() != 6 || !secret.bytes().all(|b| b.is_ascii_digit())))
                || (mode == "key" && !(16..=72).contains(&secret.len())) {
                return Err(ApiError::bad_request("Use a six-digit PIN or an API key of 16–72 bytes"));
            }
            Some(tokio::task::spawn_blocking(move || bcrypt::hash(secret, 10)).await
                .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Could not secure access key"))?
                .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Could not secure access key"))?)
        } else { None }
    } else { None };
    tokio::spawn(async move {
        let _guard = app.connection_lock.lock().await;
        let previous = super::connections::owned(&app, &owner, &id, StatusCode::NOT_FOUND).await?;
        if previous.get_bool("temporary") == Ok(true) { return Err(ApiError::bad_request("Temporary mappings are managed by the agent")); }
        let mut candidate = previous.clone();
        if mode == "off" { candidate.remove("public_access"); }
        else if let Some(verifier) = verifier {
            candidate.insert("public_access", doc! {"verifier":verifier,"pin":mode=="pin"});
        } else if !previous.get_document("public_access").is_ok_and(|value| value.get_bool("pin") == Ok(mode == "pin")) {
            return Err(ApiError::bad_request("Supply a new PIN or API key to enable this access mode"));
        }
        candidate.insert("updated_at", DateTime::now());
        app.collection("connections").replace_one(doc! {"_id":previous.get("_id")}, &candidate).await?;
        if let Err(error) = generated::rebuild(&app).await {
            super::connections::restore(&app, Some(&previous), &candidate).await;
            return Err(error);
        }
        app.notify_config(&store::id(candidate.get("machine_id"))).await;
        Ok(Json(json!({"data":{"mode":mode},"msg":"Public access lock updated"})))
    }).await.map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Access lock update failed"))?
}
