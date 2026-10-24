use crate::{
    auth,
    domain::workspaces::object_id,
    error::{ApiError, ApiResult},
    input::{ApiBody, Model},
    App,
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use serde_json::Value;
use std::sync::Arc;
pub fn router() -> Router<Arc<App>> {
    Router::new().route("/api/machines/delete", post(delete))
}
async fn delete(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let mut model = Model::new(raw)?;
    let id = model.required_string("data_id");
    model.finish()?;
    let user = auth::current_user(&app, &headers).await?;
    let id = object_id(&id, "Invalid machine id")?;
    let owner = user
        .get("_id")
        .cloned()
        .ok_or_else(ApiError::unauthenticated)?;
    let work = app.clone();
    match tokio::spawn(async move {
        let _guard = work.connection_lock.lock().await;
        crate::machine_delete::delete(&work, &owner, id)
            .await
            .map(Json)
    })
    .await
    {
        Ok(result) => {
            if result.is_err() {
                app.deletion_changes.notify_one();
            }
            result
        }
        Err(error) => {
            app.deletion_changes.notify_one();
            tracing::error!(%error,"machine deletion task stopped");
            Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
            ))
        }
    }
}
