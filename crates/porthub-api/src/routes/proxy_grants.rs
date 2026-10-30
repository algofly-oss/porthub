//! Browser-owned application proxy permissions. Agent credentials can consume
//! a grant, but cannot create one or widen another machine's permissions.
use crate::{
    error::{ApiError, ApiResult},
    input::{ApiBody, Model},
    routes::access::{browser, WorkspaceQuery},
    store, App,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode},
    routing::get,
    Json, Router,
};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime, Document};
use serde_json::{json, Value};
use std::{collections::HashSet, sync::Arc};

pub const COLLECTION: &str = "private_proxy_grants";
#[derive(Debug)]
struct GrantInput {
    name: String,
    target: Option<ObjectId>,
    clients: Vec<ObjectId>,
    enabled: bool,
    allow_lan: bool,
}
fn parse(raw: Value) -> ApiResult<GrantInput> {
    let mut model = Model::new(raw)?;
    let name = model.required_string("name").trim().to_owned();
    model.string_length("name", &name, 1, Some(80));
    let kind = model.literal("target_kind", "gateway", &["gateway", "machine"]);
    let target = if kind == "machine" {
        let value = model.required_string("target_machine_id");
        match ObjectId::parse_str(&value) {
            Ok(id) => Some(id),
            Err(_) => {
                model.add(
                    "target_machine_id",
                    "Choose a registered machine",
                    "value_error",
                );
                None
            }
        }
    } else {
        None
    };
    let mut clients = Vec::new();
    let mut seen = HashSet::new();
    for value in model.string_list("client_machine_ids", 128) {
        match ObjectId::parse_str(&value) {
            Ok(id) if seen.insert(id) => clients.push(id),
            Ok(_) => {}
            Err(_) => model.add(
                "client_machine_ids",
                "Choose registered machines",
                "value_error",
            ),
        }
    }
    if clients.is_empty() {
        model.add(
            "client_machine_ids",
            "Select machines allowed to use this proxy",
            "value_error",
        );
    }
    if target.is_some_and(|target| clients.contains(&target)) {
        model.add(
            "client_machine_ids",
            "A machine cannot use itself as a shared proxy",
            "value_error",
        );
    }
    for field in ["enabled", "allow_lan"] {
        if model
            .field(&[field])
            .is_some_and(|value| !value.is_boolean())
        {
            model.add(field, "Expected a boolean", "type_error.bool");
        }
    }
    let enabled = model.optional_bool("enabled").unwrap_or(true);
    let allow_lan = model.optional_bool("allow_lan").unwrap_or(false);
    model.finish()?;
    Ok(GrantInput {
        name,
        target,
        clients,
        enabled,
        allow_lan,
    })
}
pub(crate) fn public(record: &Document) -> Value {
    json!({"_id":store::id(record.get("_id")),"name":store::string(record,"name"),
        "target_kind":record.get_str("target_kind").unwrap_or("gateway"),
        "target_machine_id":store::id(record.get("target_machine_id")),
        "client_machine_ids":record.get_array("client_machine_ids").map(|ids|ids.iter().map(|id|store::id(Some(id))).collect::<Vec<_>>()).unwrap_or_default(),
        "enabled":record.get_bool("enabled").unwrap_or(false),"allow_lan":record.get_bool("allow_lan").unwrap_or(false)})
}
pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/access/proxy-grants", get(list).post(create))
        .route(
            "/api/access/proxy-grants/{id}",
            axum::routing::put(update).delete(remove),
        )
}
async fn list(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>,
) -> ApiResult<Json<Value>> {
    let (user, owner, _) = browser(&app, &headers, &Method::GET, &query.workspace, false).await?;
    let records: Vec<Document> = app
        .collection(COLLECTION)
        .find(doc! {"workspace_id":owner})
        .sort(doc! {"created_at":1,"_id":1})
        .await?
        .try_collect()
        .await?;
    Ok(Json(
        json!({"data":records.iter().map(public).collect::<Vec<_>>(),"can_allow_gateway_lan":store::string(&user,"role")=="admin"}),
    ))
}
async fn validate_inventory(app: &App, owner: ObjectId, input: &GrantInput) -> ApiResult<()> {
    let mut ids: HashSet<_> = input.clients.iter().copied().collect();
    ids.extend(input.target);
    let ids: Vec<_> = ids.into_iter().collect();
    if app
        .collection("machines")
        .count_documents(doc! {
            "_id":{"$in":&ids},"user_id":owner,"deletion_pending":{"$ne":true}
        })
        .await?
        != ids.len() as u64
    {
        return Err(ApiError::bad_request(
            "Proxy machines must belong to this workspace",
        ));
    }
    Ok(())
}
fn check_gateway_permission(user:&Document,input:&GrantInput)->ApiResult<()> {
    if input.target.is_none() && input.allow_lan && store::string(user,"role")!="admin" {
        return Err(ApiError::new(StatusCode::FORBIDDEN,"Gateway LAN access requires a platform administrator"));
    }
    Ok(())
}
fn document(owner: ObjectId, input: GrantInput) -> Document {
    doc! {"workspace_id":owner,"name":input.name,"target_kind":if input.target.is_some(){"machine"}else{"gateway"},
    "gateway_lan_authorized":input.target.is_none()&&input.allow_lan,
    "target_machine_id":input.target.map(Bson::ObjectId).unwrap_or(Bson::Null),"client_machine_ids":input.clients,
    "enabled":input.enabled,"allow_lan":input.allow_lan,"updated_at":DateTime::now()}
}
async fn create(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let (user, owner, _) = browser(&app, &headers, &Method::POST, &query.workspace, true).await?;
    let input = parse(raw)?;
    check_gateway_permission(&user,&input)?;
    validate_inventory(&app, owner, &input).await?;
    let _lock = app.private_network_lock.lock().await;
    if app
        .collection(COLLECTION)
        .count_documents(doc! {"workspace_id":owner})
        .await?
        >= 128
    {
        return Err(ApiError::bad_request("Too many shared proxy grants"));
    }
    let mut record = document(owner, input);
    record.insert("_id", ObjectId::new());
    record.insert("created_at", DateTime::now());
    app.collection(COLLECTION).insert_one(&record).await?;
    app.proxy_pending.invalidate(owner).await;
    Ok(Json(public(&record)))
}
async fn update(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>,
    Path(id): Path<String>,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let (user, owner, _) = browser(&app, &headers, &Method::PUT, &query.workspace, true).await?;
    let id = crate::domain::workspaces::object_id(&id, "Invalid proxy grant")?;
    let input = parse(raw)?;
    check_gateway_permission(&user,&input)?;
    validate_inventory(&app, owner, &input).await?;
    let record = document(owner, input);
    if app
        .collection(COLLECTION)
        .update_one(doc! {"_id":id,"workspace_id":owner}, doc! {"$set":&record})
        .await?
        .matched_count
        != 1
    {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Proxy grant not found",
        ));
    }
    let mut record = record;
    record.insert("_id", id);
    app.proxy_pending.invalidate(owner).await;
    Ok(Json(public(&record)))
}
async fn remove(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let (_, owner, _) = browser(&app, &headers, &Method::DELETE, &query.workspace, true).await?;
    let id = crate::domain::workspaces::object_id(&id, "Invalid proxy grant")?;
    if app
        .collection(COLLECTION)
        .delete_one(doc! {"_id":id,"workspace_id":owner})
        .await?
        .deleted_count
        != 1
    {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Proxy grant not found",
        ));
    }
    app.proxy_pending.invalidate(owner).await;
    Ok(Json(json!({"status":"ok"})))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn grant() -> Value {
        json!({"name":"Gateway proxy","client_machine_ids":["69db167e3d094f3142d04ff8"]})
    }
    #[test]
    fn explicit_clients_required_and_lan_defaults_closed() {
        let parsed = parse(grant()).ok().expect("valid grant");
        assert!(parsed.target.is_none());
        assert!(!parsed.allow_lan);
        assert!(parsed.enabled);
        let mut raw = grant();
        raw["client_machine_ids"] = json!([]);
        assert!(parse(raw).is_err());
        let mut raw = grant();
        raw["client_machine_ids"] = json!(["foreign-string"]);
        assert!(parse(raw).is_err());
    }
    #[test]
    fn target_and_privileges_are_strict_and_self_proxy_is_rejected() {
        for key in ["enabled", "allow_lan"] {
            let mut raw = grant();
            raw[key] = json!("true");
            assert!(parse(raw).is_err());
        }
        let mut raw = grant();
        raw["target_kind"] = json!("machine");
        assert!(parse(raw.clone()).is_err());
        raw["target_machine_id"] = json!("69db167e3d094f3142d04ff8");
        assert!(parse(raw.clone()).is_err());
        raw["target_machine_id"] = json!("69db167e3d094f3142d04ff9");
        assert!(parse(raw).is_ok());
    }
}
