use crate::{
    error::{ApiError, ApiResult},
    store, App,
};
use axum::http::StatusCode;
use mongodb::{
    bson::{doc, DateTime, Document},
    options::ReturnDocument,
};

pub fn clean(lines: Vec<String>) -> Vec<String> {
    lines
        .into_iter()
        .take(100)
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            line.trim_end_matches(['\r', '\n'])
                .chars()
                .take(4000)
                .collect()
        })
        .collect()
}

/// Current credentials and the bounded retained token history can report logs.
/// Unrelated tokens cannot spoof presence or inject an authentication warning.
pub async fn touch(app: &App, id: &str, token: &str) -> ApiResult<(Document, bool)> {
    let id = super::workspaces::object_id(id, "Invalid machine id")?;
    let machine = app.collection("machines").find_one(doc! {"_id":id}).await?;
    let gone = || {
        ApiError::new(StatusCode::GONE, "Machine deleted")
            .header("x-porthub-machine-deleted", "true")
    };
    let machine = machine.ok_or_else(gone)?;
    if machine.get_bool("deletion_pending") == Ok(true) {
        return Err(gone());
    }
    let current = store::string(&machine, "token");
    let known = current == token
        || machine
            .get_array("log_tokens")
            .into_iter()
            .flatten()
            .any(|value| value.as_str() == Some(token));
    if !known {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "Invalid machine credentials",
        ));
    }
    let required = current != token;
    let updated = app
        .collection("machines")
        .find_one_and_update(
            doc! {"_id":id,"token":machine.get("token"),"deletion_pending":{"$ne":true}},
            doc! {"$set":{"auth_required":required,"last_seen_at":DateTime::now()}},
        )
        .return_document(ReturnDocument::After)
        .await?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::CONFLICT,
                "Machine credentials changed; retry synchronization",
            )
        })?;
    Ok((updated, required))
}
