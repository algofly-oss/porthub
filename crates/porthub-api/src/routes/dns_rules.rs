//! Device-scoped DNS rules, delivered only on that device's authenticated sync.
use crate::{
    domain::workspaces::object_id,
    error::{ApiError, ApiResult},
    input::ApiBody,
    routes::access::{browser, WorkspaceQuery},
    store, App,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode},
    routing::get,
    Json, Router,
};
use mongodb::bson::{doc, DateTime, Document};
use porthub_mesh::dns_policy::{self, Rule};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    rules: Vec<Rule>,
}

pub fn router() -> Router<Arc<App>> {
    Router::new().route("/api/access/dns-rules/{machine}", get(load).put(save))
}

async fn load(
    State(app): State<Arc<App>>, headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>, Path(machine): Path<String>,
) -> ApiResult<Json<Value>> {
    let (_, owner, role) = browser(&app, &headers, &Method::GET, &query.workspace, false).await?;
    let machine_id = object_id(&machine, "Invalid machine id")?;
    if app.collection("machines").find_one(doc! {"_id":machine_id,"user_id":owner,"deletion_pending":{"$ne":true}}).await?.is_none() {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Machine not found in this workspace"));
    }
    let document = app.collection("private_dns_rules").find_one(doc! {"workspace_id":owner,"machine_id":machine_id}).await?;
    let rules = document.as_ref().map(|value| blocking_rules(store::field(value,"rules"))).unwrap_or_else(|| json!([]));
    Ok(Json(json!({"data":{"machine_id":machine_id.to_hex(),"rules":rules,"can_manage":matches!(role.as_str(),"owner"|"admin")}})))
}

/// Retired address rules must neither be shown nor delivered during rollout.
pub(crate) fn blocking_rules(value:Value)->Value {
    match value {
        Value::Array(rules)=>Value::Array(rules.into_iter().filter(|rule|rule["action"]["type"]!="override").collect()),
        other=>other,
    }
}
/// One bounded startup migration removes the retired settings from storage.
/// Existing block rules and machine registrations remain intact.
pub async fn remove_address_overrides(app:&App)->ApiResult<()> {
    app.collection("private_dns_rules").update_many(doc! {"rules.action.type":"override"},doc! {"$pull":{"rules":{"action.type":"override"}}}).await?;
    Ok(())
}

pub fn serialize(value: &Document) -> Value {
    json!({"machine_id":store::id(value.get("machine_id")),"rules":blocking_rules(store::field(value,"rules"))})
}

/// Caller holds connection_lock across this check and the identity-zone edit.
pub(crate) async fn ensure_zones_available(app: &App, owner: &mongodb::bson::Bson, zones: &[String]) -> ApiResult<()> {
    use futures_util::TryStreamExt;
    let policies: Vec<Document> = app.collection("private_dns_rules")
        .find(doc! {"workspace_id":owner}).await?.try_collect().await?;
    for policy in policies {
        let rules: Vec<Rule> = serde_json::from_value(blocking_rules(store::field(&policy, "rules")))
            .map_err(|_| ApiError::bad_request("Stored DNS rules need review before changing private domains"))?;
        for rule in dns_policy::prepare(&rules).map_err(|_| ApiError::bad_request("Stored DNS rules need review before changing private domains"))? {
            if zones.iter().any(|zone| dns_policy::zone(&rule) == zone || dns_policy::zone(&rule).ends_with(&format!(".{zone}")) || zone.ends_with(&format!(".{}", dns_policy::zone(&rule)))) {
                return Err(ApiError::bad_request("Private domain suffix conflicts with an existing DNS rule; change that rule first"));
            }
        }
    }
    Ok(())
}

async fn save(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>,
    Path(machine): Path<String>,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let (_, owner, _) = browser(&app, &headers, &Method::PUT, &query.workspace, true).await?;
    let machine_id = object_id(&machine, "Invalid machine id")?;
    let input: Input =
        serde_json::from_value(raw).map_err(|_| ApiError::bad_request("Invalid DNS rules"))?;
    let rules = dns_policy::prepare(&input.rules)
        .map_err(|error| ApiError::bad_request(&error.to_string()))?;
    let _guard = app.connection_lock.lock().await;
    if app
        .collection("machines")
        .find_one(doc! {"_id":machine_id,"user_id":owner,"deletion_pending":{"$ne":true}})
        .await?
        .is_none()
    {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Machine not found in this workspace",
        ));
    }
    let prefs = app
        .collection("private_networks")
        .find_one(doc! {"_id":owner.to_hex()})
        .await?
        .unwrap_or_default();
    let (_, suffix) = crate::domain::enrollment::preferences(&prefs)?;
    let mut zones = vec![suffix];
    use futures_util::TryStreamExt;
    let machines: Vec<Document> = app
        .collection("machines")
        .find(doc! {"user_id":owner})
        .projection(doc! {"private_domains":1})
        .await?
        .try_collect()
        .await?;
    for machine in machines {
        zones.extend(
            crate::domain::private_domains::from_document(&machine)
                .into_iter()
                .filter(|domain| !domain.default)
                .map(|domain| domain.suffix),
        );
    }
    for rule in &rules {
        if zones.iter().any(|zone| {
            dns_policy::zone(rule) == zone
                || dns_policy::zone(rule).ends_with(&format!(".{zone}"))
                || zone.ends_with(&format!(".{}", dns_policy::zone(rule)))
        }) {
            return Err(ApiError::bad_request(
                "DNS rule conflicts with a private identity zone",
            ));
        }
    }
    let id = format!("{owner}:{machine_id}");
    if rules.is_empty() {
        app.collection("private_dns_rules")
            .delete_one(doc! {"_id":&id,"workspace_id":owner})
            .await?;
    } else {
        let rules = mongodb::bson::to_bson(&rules)
            .map_err(|_| ApiError::bad_request("Invalid DNS rules"))?;
        app.collection("private_dns_rules").update_one(doc! {"_id":&id},doc! {"$set":{"workspace_id":owner,"machine_id":machine_id,"rules":rules,"updated_at":DateTime::now()}}).upsert(true).await?;
    }
    Ok(Json(
        json!({"data":{"machine_id":machine_id.to_hex(),"rules":rules}}),
    ))
}
