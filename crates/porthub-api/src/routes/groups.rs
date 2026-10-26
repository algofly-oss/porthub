use crate::{
    auth,
    domain::workspaces::object_id,
    error::{ApiError, ApiResult},
    input::{ApiBody, Model},
    store, App,
};
use axum::{
    extract::State,
    http::HeaderMap,
    routing::{get, post, put},
    Json, Router,
};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime, Document};
use serde_json::{json, Value};
use std::sync::Arc;

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/groups/add", post(add))
        .route("/api/groups/list", get(list))
        .route("/api/groups/update", put(update))
        .route("/api/groups/delete", post(delete))
}

fn serialize(group: &Document) -> Value {
    json!({"_id":store::id(group.get("_id")),"user_id":store::id(group.get("user_id")),
        "name":group.get("name").map(store::json).unwrap_or(json!("")),
        "sort_order":group.get("sort_order").map(store::json).unwrap_or(json!(0)),
        "created_at":store::field(group,"created_at"),"updated_at":store::field(group,"updated_at")})
}

fn fields(raw: Value, keys: &[&str]) -> ApiResult<Vec<String>> {
    let mut model = Model::new(raw)?;
    let values = keys
        .iter()
        .map(|key| {
            let value = model.required_string(key);
            model.string_length(key, &value, 1, None);
            value
        })
        .collect();
    model.finish()?;
    Ok(values)
}

async fn owned_group(app: &App, owner: &Bson, id: &str) -> ApiResult<(ObjectId, Document)> {
    let id = object_id(id, "Invalid group id")?;
    let group = app
        .collection("machine_groups")
        .find_one(doc! {"_id":id,"user_id":owner})
        .await?
        .ok_or_else(|| ApiError::bad_request("Group not found"))?;
    Ok((id, group))
}

async fn add(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let values = fields(raw, &["name"])?;
    let user = auth::current_user(&app, &headers).await?;
    let owner = user.get("_id").ok_or_else(ApiError::unauthenticated)?;
    let name = values[0].trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("Group name is required"));
    }
    let count = app
        .collection("machine_groups")
        .count_documents(doc! {"user_id":owner})
        .await?;
    let now = DateTime::now();
    let mut record = doc! {"_id":ObjectId::new(),"user_id":owner,"name":name,"sort_order":count as i64,"created_at":now,"updated_at":now};
    let inserted = app.collection("machine_groups").insert_one(&record).await?;
    record.insert("_id", inserted.inserted_id);
    Ok(Json(
        json!({"msg":"Group created successfully","data":serialize(&record)}),
    ))
}

async fn list(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let user = auth::current_user(&app, &headers).await?;
    let owner = user.get("_id").ok_or_else(ApiError::unauthenticated)?;
    let groups: Vec<Document> = app
        .collection("machine_groups")
        .find(doc! {"user_id":owner})
        .sort(doc! {"sort_order":1,"created_at":1})
        .await?
        .try_collect()
        .await?;
    Ok(Json(
        json!({"msg":"Groups listed successfully","data":groups.iter().map(serialize).collect::<Vec<_>>()}),
    ))
}

async fn update(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let values = fields(raw, &["data_id", "name"])?;
    let user = auth::current_user(&app, &headers).await?;
    let owner = user.get("_id").ok_or_else(ApiError::unauthenticated)?;
    let name = values[1].trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("Group name is required"));
    }
    let (id, mut record) = owned_group(&app, owner, &values[0]).await?;
    let now = DateTime::now();
    app.collection("machine_groups")
        .update_one(
            doc! {"_id":id,"user_id":owner},
            doc! {"$set":{"name":name,"updated_at":now}},
        )
        .await?;
    record.insert("name", name);
    record.insert("updated_at", now);
    Ok(Json(
        json!({"msg":"Group updated successfully","data":serialize(&record)}),
    ))
}

async fn delete(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let values = fields(raw, &["data_id"])?;
    let user = auth::current_user(&app, &headers).await?;
    let _guard = app.connection_lock.lock().await;
    let owner = user.get("_id").ok_or_else(ApiError::unauthenticated)?;
    let (id, group) = owned_group(&app, owner, &values[0]).await?;
    let mut proposed: Vec<Document> = app.collection("machines").find(doc! {"user_id":owner}).projection(doc! {"group_id":1,"group_ids":1}).await?.try_collect().await?;
    for machine in &mut proposed {
        let mut groups = crate::domain::inventory::group_ids(machine);
        groups.retain(|group| *group != id);
        machine.insert("group_ids", groups);
        machine.remove("group_id");
    }
    super::exit_nodes::validate_machine_changes(&app, owner, &proposed).await?;
    let now = DateTime::now();
    app.collection("machines")
        .update_many(
            doc! {"user_id":owner,"group_ids":id},
            doc! {"$pull":{"group_ids":id},"$set":{"updated_at":now}},
        )
        .await?;
    app.collection("machines")
        .update_many(
            doc! {"user_id":owner,"group_id":id},
            doc! {"$unset":{"group_id":""},"$set":{"updated_at":now}},
        )
        .await?;
    app.collection("machine_groups")
        .delete_one(doc! {"_id":id,"user_id":owner})
        .await?;
    Ok(Json(
        json!({"msg":"Group deleted successfully","data":serialize(&group)}),
    ))
}
