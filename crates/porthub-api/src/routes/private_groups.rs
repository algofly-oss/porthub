//! Workspace-scoped group mutation used by private access rules. Group labels
//! never create grants; the next authenticated sync recompiles current policy.
use crate::{
    domain::{inventory, workspaces::object_id},
    error::{ApiError, ApiResult},
    input::{ApiBody, Model},
    input_compat,
    routes::access::{browser, WorkspaceQuery},
    store, App,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode},
    routing::{post, put},
    Json, Router,
};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime, Document};
use serde_json::{json, Value};
use std::{collections::HashSet, sync::Arc};

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/access/groups", post(create))
        .route("/api/access/groups/{id}/members", put(members).patch(members))
}
async fn create(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let raw = raw.as_object().ok_or_else(|| {
        ApiError::validation(vec![
            json!({"loc":["body"],"msg":"value is not a valid dict","type":"type_error.dict"}),
        ])
    })?;
    let (_, owner, _) = browser(&app, &headers, &Method::POST, &query.workspace, true).await?;
    let name = raw.get("name").map(input_compat::text).unwrap_or_default();
    let name = input_compat::strip(&name);
    if name.is_empty() || name.chars().count() > 80 {
        return Err(ApiError::bad_request(
            "Group name must contain 1–80 characters",
        ));
    }
    let _guard = app.connection_lock.lock().await;
    if app
        .collection("machine_groups")
        .count_documents(doc! {"user_id":owner,"name":name})
        .await?
        != 0
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "A group with that name already exists",
        ));
    }
    let id = ObjectId::new();
    app.collection("machine_groups").insert_one(doc!{"_id":id,"user_id":owner,"name":name,"user_ids":[],"sort_order":0,"created_at":DateTime::now()}).await?;
    Ok(Json(
        json!({"data":{"_id":id.to_hex(),"name":name,"user_ids":[]}}),
    ))
}
fn ids(values: Vec<String>, detail: &str) -> ApiResult<Vec<ObjectId>> {
    let mut seen = HashSet::new();
    let mut output = Vec::new();
    for value in values {
        let id = object_id(&value, detail)?;
        if seen.insert(id) {
            output.push(id);
        }
    }
    Ok(output)
}
async fn members(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>,
    Path(id): Path<String>,
    method: Method,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let patch=method==Method::PATCH;
    let raw = input_compat::dictionary(raw.clone())
        .map(Value::Object)
        .unwrap_or(raw);
    let mut model = Model::new(raw)?;
    let machines = model.string_list(if patch {"machine_add"}else{"machine_ids"}, 1000);
    let users = model.string_list(if patch {"user_add"}else{"user_ids"}, 1000);
    let machine_remove=if patch {model.string_list("machine_remove",1000)}else{Vec::new()};
    let user_remove=if patch {model.string_list("user_remove",1000)}else{Vec::new()};
    model.finish()?;
    let (_, owner, _) = browser(&app, &headers, &method, &query.workspace, true).await?;
    let group = object_id(&id, "Invalid group")?;
    let _guard = app.connection_lock.lock().await;
    let group_record=app.collection("machine_groups").find_one(doc! {"_id":group,"user_id":owner}).await?.ok_or_else(||ApiError::new(StatusCode::NOT_FOUND,"Group not found"))?;
    let mut machines = ids(machines, "Invalid machine")?;
    let mut users = ids(users, "Invalid user")?;
    let added_users=users.clone();
    if patch {
        let machine_remove=ids(machine_remove,"Invalid machine")?;
        let user_remove=ids(user_remove,"Invalid user")?;
        if machines.iter().any(|id|machine_remove.contains(id)) || users.iter().any(|id|user_remove.contains(id)) {return Err(ApiError::bad_request("A member cannot be added and removed in the same request"));}
        // Resolve the complete existing membership under the same mutation lock.
        // A page of checkboxes changes only explicitly edited IDs.
        let existing=app.collection("machines").find(doc! {"user_id":owner}).projection(doc! {"group_id":1,"group_ids":1}).await?.try_collect::<Vec<_>>().await?;
        let mut selected=existing.iter().filter(|record|inventory::group_ids(record).contains(&group)).filter_map(|record|record.get_object_id("_id").ok()).filter(|id|!machine_remove.contains(id)).collect::<HashSet<_>>();
        selected.extend(machines);machines=selected.into_iter().collect();
        let mut selected=group_record.get_array("user_ids").ok().into_iter().flatten().filter_map(|id|ObjectId::parse_str(store::id(Some(id))).ok()).filter(|id|!user_remove.contains(id)).collect::<HashSet<_>>();
        selected.extend(users);users=selected.into_iter().collect();
    }
    if !machines.is_empty()
        && app
            .collection("machines")
            .count_documents(doc! {"user_id":owner,"_id":{"$in":&machines}})
            .await?
            != machines.len() as u64
    {
        return Err(ApiError::bad_request(
            "Selected machines must belong to this workspace",
        ));
    }
    let memberships: Vec<Document> = app
        .collection("workspace_members")
        .find(doc! {"workspace_id":owner})
        .projection(doc! {"user_id":1})
        .await?
        .try_collect()
        .await?;
    let mut allowed = HashSet::from([owner]);
    for member in memberships {
        if let Ok(id) = ObjectId::parse_str(store::id(member.get("user_id"))) {
            allowed.insert(id);
        }
    }
    if patch && added_users.iter().any(|id| !allowed.contains(id)) {return Err(ApiError::bad_request("Selected users must belong to this workspace"));}
    if patch {users.retain(|id|allowed.contains(id));}
    if users.iter().any(|id| !allowed.contains(id)) {
        return Err(ApiError::bad_request(
            "Selected users must belong to this workspace",
        ));
    }
    // Preserve a legacy single group before modern add/pull operations. The
    // comparison prevents replacing an array concurrently saved by a client.
    let records: Vec<Document> = app
        .collection("machines")
        .find(doc! {"user_id":owner})
        .projection(doc! {"group_id":1,"group_ids":1})
        .await?
        .try_collect()
        .await?;
    let proposed: Vec<Document> = records.iter().map(|record| {
        let mut changed = record.clone();
        let mut groups = inventory::group_ids(record);
        groups.retain(|id| *id != group);
        if record.get_object_id("_id").is_ok_and(|id| machines.contains(&id)) { groups.push(group); }
        changed.insert("group_ids", groups);
        changed.remove("group_id");
        changed
    }).collect();
    super::exit_nodes::validate_machine_changes(&app, &Bson::ObjectId(owner), &proposed).await?;
    for record in records {
        if record
            .get("group_id")
            .is_some_and(|value| input_compat::truthy(&store::json(value)))
            && !record
                .get("group_ids")
                .is_some_and(|value| input_compat::truthy(&store::json(value)))
        {
            let groups = inventory::group_ids(&record);
            app.collection("machines").update_one(doc!{"_id":record.get("_id"),"user_id":owner,"group_ids":record.get("group_ids").unwrap_or(&Bson::Null)},doc!{"$set":{"group_ids":groups},"$unset":{"group_id":""}}).await?;
        }
    }
    if !machines.is_empty() {
        app.collection("machines")
            .update_many(
                doc! {"user_id":owner,"_id":{"$in":&machines}},
                doc! {"$addToSet":{"group_ids":group}},
            )
            .await?;
    }
    app.collection("machines").update_many(doc!{"user_id":owner,"_id":{"$nin":&machines}},doc!{"$pull":{"group_ids":{"$in":[Bson::ObjectId(group),Bson::String(group.to_hex())]}}}).await?;
    app.collection("machine_groups")
        .update_one(
            doc! {"_id":group,"user_id":owner},
            doc! {"$set":{"user_ids":users,"updated_at":DateTime::now()}},
        )
        .await?;
    Ok(Json(json!({"msg":"Group members saved"})))
}
