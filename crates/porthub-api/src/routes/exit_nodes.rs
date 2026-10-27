//! Workspace-scoped IPv4 exit-node definitions. Selectors remain dynamic so
//! machines added to a selected group inherit that group's route assignment.
use crate::{
    domain::{inventory, workspaces::object_id},
    error::{ApiError, ApiResult},
    input::{ApiBody, Model},
    routes::access::{browser, WorkspaceQuery},
    store, App,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode},
    routing::post,
    Json, Router,
};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime, Document};
use serde_json::{json, Value};
use std::{collections::HashSet, sync::Arc};

#[derive(Clone, Debug)]
struct Selector {
    kind: String,
    id: String,
}

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/access/exit-nodes", post(create))
        .route(
            "/api/access/exit-nodes/{id}",
            axum::routing::put(update).delete(delete),
        )
}

fn selectors(model: &mut Model, key: &str, allow_empty: bool) -> Vec<Selector> {
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    for mut child in model.objects(key, false, if allow_empty { 0 } else { 1 }, 32) {
        let kind = child.literal("kind", "", &["machine", "group"]);
        let id = child.required_string("id");
        child.string_length("id", &id, 24, Some(24));
        let id = id.to_ascii_lowercase();
        if child.field_valid("id") && ObjectId::parse_str(&id).is_err() {
            child.add("id", "Invalid machine or group id", "value_error");
        }
        if child.is_valid() && seen.insert((kind.clone(), id.clone())) {
            result.push(Selector { kind, id });
        }
        model.merge(child);
    }
    if result.is_empty() && !allow_empty {
        model.add(key, "Select at least one machine or group", "value_error");
    }
    result
}

fn selector_docs(values: &[Selector]) -> Vec<Bson> {
    values
        .iter()
        .map(|value| Bson::Document(doc! {"kind":&value.kind,"id":&value.id}))
        .collect()
}

fn read_selectors(route: &Document, key: &str) -> ApiResult<Vec<Selector>> {
    let mut output = Vec::new();
    for item in route
        .get_array(key)
        .map_err(|_| ApiError::bad_request("Invalid exit-node selectors"))?
    {
        let Bson::Document(item) = item else {
            return Err(ApiError::bad_request("Invalid exit-node selectors"));
        };
        let kind = store::string(item, "kind").to_owned();
        let id = store::string(item, "id").to_owned();
        if !["machine", "group"].contains(&kind.as_str()) || ObjectId::parse_str(&id).is_err() {
            return Err(ApiError::bad_request("Invalid exit-node selectors"));
        }
        output.push(Selector { kind, id });
    }
    Ok(output)
}

async fn machine_ids(
    app: &App,
    owner: ObjectId,
    selectors: &[Selector],
) -> ApiResult<HashSet<ObjectId>> {
    let machines: Vec<Document> = app
        .collection("machines")
        .find(doc! {"user_id":owner,"deletion_pending":{"$ne":true}})
        .projection(doc! {"_id":1,"group_ids":1,"group_id":1})
        .await?
        .try_collect()
        .await?;
    let mut groups = HashSet::new();
    let direct: Vec<ObjectId> = selectors
        .iter()
        .filter(|s| s.kind == "machine")
        .map(|s| object_id(&s.id, "Invalid machine selector"))
        .collect::<ApiResult<_>>()?;
    let selected_groups: Vec<ObjectId> = selectors
        .iter()
        .filter(|s| s.kind == "group")
        .map(|s| object_id(&s.id, "Invalid group selector"))
        .collect::<ApiResult<_>>()?;
    if !direct.is_empty()
        && app
            .collection("machines")
            .count_documents(
                doc! {"user_id":owner,"_id":{"$in":&direct},"deletion_pending":{"$ne":true}},
            )
            .await?
            != direct.len() as u64
    {
        return Err(ApiError::bad_request(
            "Selected machines must belong to this workspace",
        ));
    }
    if !selected_groups.is_empty()
        && app
            .collection("machine_groups")
            .count_documents(doc! {"user_id":owner,"_id":{"$in":&selected_groups}})
            .await?
            != selected_groups.len() as u64
    {
        return Err(ApiError::bad_request(
            "Selected groups must belong to this workspace",
        ));
    }
    groups.extend(selected_groups);
    let mut output: HashSet<ObjectId> = direct.into_iter().collect();
    for machine in machines {
        let id = machine
            .get_object_id("_id")
            .map_err(|_| ApiError::bad_request("Invalid machine inventory"))?;
        if inventory::group_ids(&machine)
            .iter()
            .any(|group| groups.contains(group))
        {
            output.insert(id);
        }
    }
    Ok(output)
}

pub(crate) fn matches_selectors(
    route: &Document,
    key: &str,
    machine_id: &str,
    machine: &Document,
) -> bool {
    selector_priority(route, key, machine_id, machine).is_some()
}

/// First selector wins; direct machines and dynamic groups share one priority
/// order. The authenticated inventory supplies group membership.
pub(crate) fn selector_priority(
    route: &Document,
    key: &str,
    machine_id: &str,
    machine: &Document,
) -> Option<usize> {
    route.get_array(key).ok()?.iter().position(|selector| {
        let Some(selector) = selector.as_document() else { return false; };
        match store::string(selector, "kind") {
            "machine" => store::string(selector, "id") == machine_id,
            "group" => ObjectId::parse_str(store::string(selector, "id"))
                .ok().is_some_and(|group| inventory::group_ids(machine).contains(&group)),
            _ => false,
        }
    })
}

async fn validate_routing_peers(
    app: &App,
    owner: ObjectId,
    selectors: &[Selector],
) -> ApiResult<()> {
    let machines = machine_ids(app, owner, selectors).await?;
    if machines.is_empty() {
        if selectors.is_empty() { return Ok(()); }
        return Err(ApiError::bad_request(
            "Routing-peer selections contain no machines",
        ));
    }
    let peers = app.collection("private_peers").count_documents(doc! {
        "workspace_id":owner,"machine_id":{"$in":machines.into_iter().map(Bson::ObjectId).collect::<Vec<_>>()},"enabled":{"$ne":false},"credential_hash":{"$ne":""}
    }).await?;
    if peers == 0 {
        return Err(ApiError::bad_request(
            "Routing peers must have an enrolled private-network client",
        ));
    }
    Ok(())
}

async fn require_tor_support(app: &App, owner: ObjectId, machines: &HashSet<ObjectId>) -> ApiResult<()> {
    let capable: Vec<Document> = app.collection("private_peers").find(doc! {
        "workspace_id":owner,"enabled":true,"tor_exit":true,
        "machine_id":{"$in":machines.iter().copied().collect::<Vec<_>>()}
    }).projection(doc! {"machine_id":1}).await?.try_collect().await?;
    let capable: HashSet<ObjectId> = capable.iter().filter_map(|peer| peer.get_object_id("machine_id").ok()).collect();
    if !machines.is_subset(&capable) {
        return Err(ApiError::bad_request("Selected machines must advertise local Tor exit support before this rule can be enabled"));
    }
    Ok(())
}

async fn require_lan_support(app: &App, owner: ObjectId, machines: &HashSet<ObjectId>) -> ApiResult<()> {
    let capable: Vec<Document> = app.collection("private_peers").find(doc! {
        "workspace_id":owner,"enabled":true,"lan_exit":true,
        "machine_id":{"$in":machines.iter().copied().collect::<Vec<_>>()}
    }).projection(doc! {"machine_id":1}).await?.try_collect().await?;
    let capable: HashSet<ObjectId> = capable.iter().filter_map(|peer| peer.get_object_id("machine_id").ok()).collect();
    if !machines.is_subset(&capable) {
        return Err(ApiError::bad_request("Selected machines must advertise LAN exit support before this traffic mode can be enabled"));
    }
    Ok(())
}

async fn reject_overlapping_assignments(
    app: &App,
    owner: ObjectId,
    candidate: &Document,
    exclude: Option<ObjectId>,
) -> ApiResult<()> {
    if candidate.get_bool("enabled") == Ok(false) {
        return Ok(());
    }
    let candidate_machines = machine_ids(
        app,
        owner,
        &read_selectors(candidate, "distribution_selectors")?,
    )
    .await?;
    if candidate_machines.is_empty() {
        return Err(ApiError::bad_request(
            "Select machines that will use this exit node",
        ));
    }
    if candidate.get_bool("tor_enabled") == Ok(true) {
        require_tor_support(app, owner, &candidate_machines).await?;
    }
    let candidate_peers = machine_ids(
        app,
        owner,
        &read_selectors(candidate, "routing_selectors")?,
    ).await?;
    if candidate.get_str("traffic_mode").unwrap_or("internet_only") != "internet_only" {
        require_lan_support(app, owner, &candidate_machines).await?;
        require_lan_support(app, owner, &candidate_peers).await?;
    }
    if !candidate_machines.is_disjoint(&candidate_peers) {
        return Err(ApiError::bad_request(
            "A routing peer cannot use its own exit node",
        ));
    }
    let mut filter = doc! {"workspace_id":owner,"enabled":{"$ne":false}};
    if let Some(id) = exclude {
        filter.insert("_id", doc! {"$ne":id});
    }
    let existing: Vec<Document> = app
        .collection("private_exit_nodes")
        .find(filter)
        .await?
        .try_collect()
        .await?;
    for route in existing {
        let assigned = machine_ids(
            app,
            owner,
            &read_selectors(&route, "distribution_selectors")?,
        )
        .await?;
        if candidate_machines.intersection(&assigned).next().is_some() {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "A machine cannot use more than one enabled exit node",
            ));
        }
        let routing = machine_ids(
            app,
            owner,
            &read_selectors(&route, "routing_selectors")?,
        ).await?;
        if !candidate_peers.is_disjoint(&assigned) || !candidate_machines.is_disjoint(&routing) {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "Routing peers cannot also use an enabled exit node",
            ));
        }
    }
    Ok(())
}

fn parse(raw: Value) -> ApiResult<(String, Vec<Selector>, Vec<Selector>, bool, String, bool, bool, i64, String)> {
    let mut model = Model::new(raw)?;
    let name = model.required_string("name");
    model.string_length("name", &name, 1, Some(80));
    let name = name.trim().to_owned();
    if name.is_empty() {
        model.add("name", "An exit-node name is required", "value_error");
    }
    if model.field(&["tor_enabled"]).is_some_and(|value| !value.is_boolean()) { model.add("tor_enabled", "Expected a boolean", "type_error.bool"); }
    let tor_enabled = if model.field(&["tor_enabled"]).is_some() { model.required_bool("tor_enabled") } else { false };
    let tor_circuit_groups = match model.field(&["tor_circuit_groups"]) {
        None => 4,
        Some(value) => match value.as_i64() {
            Some(value) if (1..=16).contains(&value) => value,
            _ => { model.add("tor_circuit_groups", "Choose between 1 and 16 Tor circuit groups", "value_error"); 4 }
        }
    };
    let routing = selectors(&mut model, "routing_selectors", tor_enabled);
    let distribution = selectors(&mut model, "distribution_selectors", false);
    let enabled = if model.field(&["enabled"]).is_some() {
        model.required_bool("enabled")
    } else {
        true
    };
    let traffic_mode = model.literal("traffic_mode", "internet_only", &["all", "internet_only", "lan_only"]);
    if traffic_mode == "lan_only" && tor_enabled {model.add("tor_enabled", "Tor carries internet traffic; disable it for LAN only", "value_error");}
    if traffic_mode == "lan_only" && routing.is_empty() {
        model.add("routing_selectors", "LAN only requires a machine or group exit; Tor cannot reach private networks", "value_error");
    }
    let selection = model.literal("selection", "sticky", &["sticky", "round_robin", "random"]);
    if model.field(&["allow_direct_fallback"]).is_some_and(|value| !value.is_boolean()) {
        model.add("allow_direct_fallback", "Expected a boolean", "type_error.bool");
    }
    let allow_direct_fallback = model.optional_bool("allow_direct_fallback").unwrap_or(false);
    model.finish()?;
    Ok((name, routing, distribution, enabled, selection, allow_direct_fallback, tor_enabled, tor_circuit_groups, traffic_mode))
}

async fn create(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let (name, routing, distribution, enabled, selection, allow_direct_fallback, tor_enabled, tor_circuit_groups, traffic_mode) = parse(raw)?;
    let (_, owner, _) = browser(&app, &headers, &Method::POST, &query.workspace, true).await?;
    let _guard = app.connection_lock.lock().await;
    let owner_id = owner;
    validate_routing_peers(&app, owner_id, &routing).await?;
    if app
        .collection("private_exit_nodes")
        .find_one(doc! {"workspace_id":owner_id,"name":&name})
        .await?
        .is_some()
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "An exit node with that name already exists",
        ));
    }
    let now = DateTime::now();
    let route = doc! {"_id":ObjectId::new(),"workspace_id":owner_id,"name":&name,"routing_selectors":selector_docs(&routing),"distribution_selectors":selector_docs(&distribution),"enabled":enabled,"selection":selection,"allow_direct_fallback":allow_direct_fallback,"tor_enabled":tor_enabled,"tor_circuit_groups":tor_circuit_groups,"traffic_mode":&traffic_mode,"masquerade":true,"block_lan_access":traffic_mode == "internet_only","created_at":now,"updated_at":now};
    reject_overlapping_assignments(&app, owner_id, &route, None).await?;
    app.collection("private_exit_nodes")
        .insert_one(&route)
        .await?;
    Ok(Json(json!({"data":serialize(&route)})))
}

async fn update(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>,
    Path(id): Path<String>,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let (name, routing, distribution, enabled, selection, allow_direct_fallback, tor_enabled, tor_circuit_groups, traffic_mode) = parse(raw)?;
    let (_, owner, _) = browser(&app, &headers, &Method::PUT, &query.workspace, true).await?;
    let owner_id = owner;
    let route_id = object_id(&id, "Invalid exit-node id")?;
    let _guard = app.connection_lock.lock().await;
    validate_routing_peers(&app, owner_id, &routing).await?;
    if app
        .collection("private_exit_nodes")
        .find_one(doc! {"workspace_id":owner_id,"name":&name,"_id":{"$ne":route_id}})
        .await?
        .is_some()
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "An exit node with that name already exists",
        ));
    }
    let previous = app
        .collection("private_exit_nodes")
        .find_one(doc! {"_id":route_id,"workspace_id":owner_id})
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Exit node not found"))?;
    let candidate = doc! {"_id":route_id,"workspace_id":owner_id,"name":&name,"routing_selectors":selector_docs(&routing),"distribution_selectors":selector_docs(&distribution),"enabled":enabled,"selection":selection,"allow_direct_fallback":allow_direct_fallback,"tor_enabled":tor_enabled,"tor_circuit_groups":tor_circuit_groups,"traffic_mode":&traffic_mode,"masquerade":true,"block_lan_access":traffic_mode == "internet_only","created_at":previous.get("created_at").cloned().unwrap_or(Bson::DateTime(DateTime::now())),"updated_at":DateTime::now()};
    reject_overlapping_assignments(&app, owner_id, &candidate, Some(route_id)).await?;
    app.collection("private_exit_nodes")
        .replace_one(doc! {"_id":route_id,"workspace_id":owner_id}, &candidate)
        .await?;
    Ok(Json(json!({"data":serialize(&candidate)})))
}

async fn delete(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let (_, owner, _) = browser(&app, &headers, &Method::DELETE, &query.workspace, true).await?;
    let route_id = object_id(&id, "Invalid exit-node id")?;
    let result = app
        .collection("private_exit_nodes")
        .delete_one(doc! {"_id":route_id,"workspace_id":owner})
        .await?;
    if result.deleted_count == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Exit node not found"));
    }
    Ok(Json(json!({"msg":"Exit node deleted"})))
}

pub fn serialize(route: &Document) -> Value {
    let selectors = |key| {
        route
            .get_array(key)
            .into_iter()
            .flatten()
            .filter_map(Bson::as_document)
            .map(|s| json!({"kind":store::string(s,"kind"),"id":store::string(s,"id")}))
            .collect::<Vec<_>>()
    };
    json!({"_id":store::id(route.get("_id")),"name":store::string(route,"name"),"routing_selectors":selectors("routing_selectors"),"distribution_selectors":selectors("distribution_selectors"),"enabled":route.get_bool("enabled").unwrap_or(true),"selection":route.get_str("selection").unwrap_or("sticky"),"allow_direct_fallback":route.get_bool("allow_direct_fallback").unwrap_or(false),"tor_enabled":route.get_bool("tor_enabled").unwrap_or(false),"tor_circuit_groups":route.get_i64("tor_circuit_groups").unwrap_or(4),"traffic_mode":route.get_str("traffic_mode").unwrap_or("internet_only"),"masquerade":true,"block_lan_access":route.get_str("traffic_mode").unwrap_or("internet_only") == "internet_only","created_at":store::field(route,"created_at"),"updated_at":store::field(route,"updated_at")})
}

/// Validate the complete enabled route graph against proposed machine records.
/// Call under connection_lock, before committing a membership change.
pub(crate) async fn validate_machine_changes(app: &App, owner: &Bson, proposed: &[Document]) -> ApiResult<()> {
    let routes: Vec<Document> = app.collection("private_exit_nodes").find(doc! {"workspace_id":owner,"enabled":{"$ne":false}}).await?.try_collect().await?;
    if routes.is_empty() { return Ok(()); }
    let mut machines: Vec<Document> = app.collection("machines").find(doc! {"user_id":owner,"deletion_pending":{"$ne":true}}).projection(doc! {"_id":1,"group_ids":1,"group_id":1}).await?.try_collect().await?;
    for changed in proposed {
        machines.retain(|record| record.get("_id") != changed.get("_id"));
        machines.push(changed.clone());
    }
    let mut clients = HashSet::new();
    let mut peers = HashSet::new();
    for route in &routes {
        let routing: HashSet<String> = machines.iter().filter(|machine| matches_selectors(route, "routing_selectors", &store::id(machine.get("_id")), machine)).map(|machine| store::id(machine.get("_id"))).collect();
        let consuming: HashSet<String> = machines.iter().filter(|machine| matches_selectors(route, "distribution_selectors", &store::id(machine.get("_id")), machine)).map(|machine| store::id(machine.get("_id"))).collect();
        if route.get_bool("tor_enabled") == Ok(true) {
            let owner=owner.as_object_id().ok_or_else(||ApiError::bad_request("Invalid exit-node workspace"))?;
            let ids=consuming.iter().map(|id|object_id(id,"Invalid Tor client")).collect::<ApiResult<HashSet<_>>>()?;
            require_tor_support(app,owner,&ids).await?;
        }
        if route.get_str("traffic_mode").unwrap_or("internet_only") != "internet_only" {
            let owner = owner.as_object_id().ok_or_else(|| ApiError::bad_request("Invalid exit-node workspace"))?;
            let ids = consuming.union(&routing).map(|id| object_id(id, "Invalid LAN exit client")).collect::<ApiResult<HashSet<_>>>()?;
            require_lan_support(app, owner, &ids).await?;
        }
        if !consuming.is_empty() && routing.is_empty() && route.get_bool("tor_enabled") != Ok(true) {
            return Err(ApiError::new(StatusCode::CONFLICT, "This group change would leave an enabled exit node without routing peers"));
        }
        if !clients.is_disjoint(&consuming) {
            return Err(ApiError::new(StatusCode::CONFLICT, "This group change would assign a machine to multiple enabled exit nodes"));
        }
        clients.extend(consuming);
        peers.extend(routing);
    }
    if !clients.is_disjoint(&peers) {
        return Err(ApiError::new(StatusCode::CONFLICT, "This group change would make an exit routing peer also consume an exit route"));
    }
    Ok(())
}


#[cfg(test)]
mod tor_tests {
    use super::*;
    fn route() -> Value { json!({"name":"Tor","routing_selectors":[],"distribution_selectors":[{"kind":"machine","id":"69db167e3d094f3142d04ff8"}],"tor_enabled":true}) }
    #[test]
    fn tor_only_route_needs_no_remote_peer_but_requires_explicit_enable() {
        let parsed=parse(route()).ok().expect("valid Tor route"); assert!(parsed.1.is_empty()); assert!(parsed.6);assert_eq!(parsed.7,4);
        let mut ordinary=route();ordinary["tor_enabled"]=json!(false);assert!(parse(ordinary).is_err());
    }
    #[test]
    fn tor_limits_and_boolean_types_are_validated() {
        for count in [json!(0),json!(17),json!("4"),json!(4.5)] {
            let mut raw=route();raw["tor_circuit_groups"]=count;assert!(parse(raw).is_err());
        }
        let mut raw=route();raw["tor_enabled"]=json!("true");assert!(parse(raw).is_err());
    }
    #[test]
    fn traffic_modes_default_safely_and_lan_needs_a_real_exit() {
        assert_eq!(parse(route()).ok().expect("valid default route").8, "internet_only");
        let mut raw = route();
        raw["traffic_mode"] = json!("lan_only");
        assert!(parse(raw.clone()).is_err());
        raw["routing_selectors"] = json!([{"kind":"machine","id":"69db167e3d094f3142d04ff9"}]);
        for mode in ["all", "internet_only", "lan_only"] {
            raw["traffic_mode"] = json!(mode);
            raw["tor_enabled"] = json!(mode != "lan_only");
            assert_eq!(parse(raw.clone()).ok().expect("valid traffic mode").8, mode);
        }
        for invalid in [json!("public"), json!(true), json!(null)] {
            raw["traffic_mode"] = invalid;
            assert!(parse(raw.clone()).is_err());
        }
    }

    #[test]
    fn selector_priority_respects_group_order_and_first_match() {
        let machine = ObjectId::new();
        let group = ObjectId::new();
        let other = ObjectId::new();
        let inventory = doc! {"_id":machine,"group_ids":[group]};
        let route = doc! {"routing_selectors":[
            {"kind":"machine","id":other.to_hex()},
            {"kind":"group","id":group.to_hex()},
            {"kind":"machine","id":machine.to_hex()}
        ]};
        assert_eq!(selector_priority(&route, "routing_selectors", &machine.to_hex(), &inventory), Some(1));
        assert_eq!(selector_priority(&route, "routing_selectors", &other.to_hex(), &doc!{}), Some(0));
        assert_eq!(selector_priority(&route, "routing_selectors", &ObjectId::new().to_hex(), &doc!{}), None);
    }
}
