//! Bounded, owner-scoped inventory queries. Matching and pagination run inside
//! MongoDB; only the requested page is serialized and sent to the browser.
use crate::{
    auth,
    domain::inventory,
    error::{ApiError, ApiResult},
    store, App,
};
use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use futures_util::TryStreamExt;
use mongodb::{
    bson::{self, doc, oid::ObjectId, Bson, Document},
    options::{Collation, CollationStrength},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct Params {
    pub q: String,
    pub page: u64,
    pub page_size: u64,
    pub sort: String,
    pub status: String,
    pub group: String,
    pub machine: String,
    pub connection: String,
    pub role: String,
    pub options: bool,
    pub ids: String,
    pub seconds: u64,
    pub since: u64,
    pub expanded: String,
    pub known: String,
    pub account: String,
    pub workspace: String,
    pub detail: bool,
    pub membership: String,
    pub entity_types: String,
    pub row_cursors: String,
    pub scope_revision: String,
    pub aggregate_token: String,
    pub row_tokens: String,
}
impl Default for Params {
    fn default() -> Self {
        Self {
            q: String::new(),
            page: 1,
            page_size: 25,
            sort: "name".into(),
            status: "all".into(),
            group: "all".into(),
            machine: "all".into(),
            connection: String::new(),
            role: "all".into(),
            options: false,
            ids: String::new(),
            seconds: 30,
            since: 0,
            expanded: String::new(),
            known: String::new(),
            account: String::new(),
            workspace: String::new(),
            detail: false,
            membership: String::new(),
            entity_types: String::new(),
            row_cursors: String::new(),
            scope_revision: String::new(),
            aggregate_token: String::new(),
            row_tokens: String::new(),
        }
    }
}
impl Params {
    pub fn row_token(&self, id: &str) -> &str {
        self.row_tokens
            .split(',')
            .filter_map(|row| row.split_once(':'))
            .find(|(key, _)| *key == id)
            .map(|(_, token)| token)
            .unwrap_or("")
    }
    pub fn row_cursor(&self, id: &str) -> Option<u64> {
        self.row_cursors
            .split(',')
            .filter_map(|row| row.split_once(':'))
            .find(|(key, _)| *key == id)
            .and_then(|(_, time)| time.parse().ok())
    }
    pub fn validate(&self) -> ApiResult<()> {
        if self.page == 0 || self.page > 1_000_000 || self.page_size == 0 || self.page_size > 100 {
            return Err(ApiError::bad_request(
                "Page must be positive; page size must be 1–100",
            ));
        }
        let valid_token = |token: &str| {
            token.len() <= 22
                && token
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        };
        if !valid_token(&self.aggregate_token) {
            return Err(ApiError::bad_request("Invalid aggregate token"));
        }
        if !self.row_tokens.is_empty() {
            let rows = self.row_tokens.split(',').collect::<Vec<_>>();
            if rows.len() > 100
                || rows.iter().any(|row| {
                    row.split_once(':').is_none_or(|(id, token)| {
                        ObjectId::parse_str(id).is_err() || !valid_token(token)
                    })
                })
            {
                return Err(ApiError::bad_request("Invalid traffic series tokens"));
            }
        }
        if self.scope_revision.len() > 64
            || (!self.scope_revision.is_empty()
                && !self.scope_revision.chars().all(|c| c.is_ascii_hexdigit()))
        {
            return Err(ApiError::bad_request("Invalid traffic scope revision"));
        }
        if !self.row_cursors.is_empty() {
            let rows = self.row_cursors.split(',').collect::<Vec<_>>();
            if rows.len() > 100
                || rows.iter().any(|row| {
                    row.split_once(':').is_none_or(|(id, time)| {
                        ObjectId::parse_str(id).is_err() || time.parse::<u64>().is_err()
                    })
                })
            {
                return Err(ApiError::bad_request(
                    "Traffic cursors support at most 100 ID:timestamp pairs",
                ));
            }
        }
        if self.detail
            && (self.ids.is_empty() || self.ids.split(',').count() != 1 || self.page_size != 1)
        {
            return Err(ApiError::bad_request(
                "Detail reads require one ID and page size 1",
            ));
        }
        if self.known.split(',').count() > 100 {
            return Err(ApiError::bad_request(
                "At most 100 known traffic rows are supported",
            ));
        }
        if self.seconds == 0 || self.seconds > 300 {
            return Err(ApiError::bad_request(
                "Traffic window must be 1–300 seconds",
            ));
        }
        if self.q.chars().count() > 256 || self.q.split_whitespace().count() > 6 {
            return Err(ApiError::bad_request(
                "Search supports up to six words and 256 characters total",
            ));
        }
        Ok(())
    }
}
pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/inventory/{kind}", get(page))
        .route("/api/inventory-status", get(status))
        .route("/api/inventory/status", get(status))
        .route("/api/inventory/machine-traffic", get(machine_traffic))
        .route("/api/inventory/summary", get(summary))
        .route(
            "/api/inventory/proxy-activity",
            get(crate::web_activity::activity),
        )
}
fn text(expr: impl Into<Bson>) -> Bson {
    doc! {"$convert":{"input":expr.into(),"to":"string","onError":"","onNull":""}}.into()
}
fn fields(names: &[&str]) -> Bson {
    Bson::Array(names.iter().map(|s| text(format!("${s}"))).collect())
}
fn list_fields(path: &str, names: &[&str]) -> Bson {
    doc!{"$map":{"input":{"$ifNull":[format!("${path}"),[]]},"as":"row","in":{"$concat":names.iter().enumerate().flat_map(|(i,name)|{let mut parts=Vec::new();if i>0{parts.push(Bson::String(" ".into()));}parts.push(text(format!("$$row.{name}")));parts}).collect::<Vec<_>>()}}}.into()
}
fn joined(
    collection: &str,
    local: &str,
    foreign: &str,
    owner: Bson,
    project: Document,
    output: &str,
) -> Document {
    doc! {"$lookup":{"from":collection,"let":{"key":format!("${local}")},"pipeline":[{"$match":{"user_id":owner,"$expr":{"$eq":[format!("${foreign}"),"$$key"]}}},{"$project":project}],"as":output}}
}
fn peers(owner: Bson) -> Document {
    doc! {"$lookup":{"from":"private_peers","let":{"machine":"$_id","revoked":{"$ifNull":["$private_owner_revoked",false]}},"pipeline":[{"$match":{"owner_id":owner,"enabled":true,"$expr":{"$and":[{"$ne":["$$revoked",true]},{"$eq":["$machine_id","$$machine"]}]}}},{"$project":{"ip":1,"hostname":1,"machine_id":1,"workspace_id":1,"_id":1}}],"as":"_peers"}}
}
// Use the existing naming algorithm (including collision suffixes) so paged
// inventory links remain identical to private DNS without preloading access UI.
pub(crate) async fn private_domains(
    app: &App,
    result: &Document,
) -> ApiResult<std::collections::HashMap<String, String>> {
    let requested = result
        .get_array("data")
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Bson::as_document)
        .filter(|row| row.get_bool("private_owner_revoked") != Ok(true))
        .flat_map(|row| row.get_array("_peers").ok().into_iter().flatten())
        .filter_map(Bson::as_document)
        .collect::<Vec<_>>();
    let mut seen_workspaces = std::collections::HashSet::new();
    let workspaces = requested
        .iter()
        .filter_map(|peer| peer.get("workspace_id").cloned())
        .filter(|id| seen_workspaces.insert(store::id(Some(id))))
        .collect::<Vec<_>>();
    if workspaces.is_empty() {
        return Ok(Default::default());
    }
    let peers = app
        .collection("private_peers")
        .find(doc! {"workspace_id":{"$in":&workspaces}})
        .projection(doc! {"machine_id":1,"hostname":1,"created_at":1,"workspace_id":1})
        .await?
        .try_collect::<Vec<_>>()
        .await?;
    let machine_ids = peers
        .iter()
        .filter_map(|p| p.get("machine_id").cloned())
        .collect::<Vec<_>>();
    let machines = app
        .collection("machines")
        .find(doc! {"_id":{"$in":machine_ids},"deletion_pending":{"$ne":true}})
        .projection(doc! {"name":1})
        .await?
        .try_collect::<Vec<_>>()
        .await?;
    let network_ids = workspaces
        .iter()
        .map(|id| Bson::String(store::id(Some(id))))
        .collect::<Vec<_>>();
    let networks = app
        .collection("private_networks")
        .find(doc! {"_id":{"$in":network_ids}})
        .projection(doc! {"dns_suffix":1})
        .await?
        .try_collect::<Vec<_>>()
        .await?;
    let mut domains = std::collections::HashMap::new();
    for workspace in workspaces {
        let workspace_peers = peers
            .iter()
            .filter(|p| p.get("workspace_id") == Some(&workspace))
            .cloned()
            .collect::<Vec<_>>();
        let labels = crate::domain::private_names::assign(&machines, &workspace_peers);
        let network = networks
            .iter()
            .find(|n| store::id(n.get("_id")) == store::id(Some(&workspace)));
        let suffix = network
            .map(|n| store::string(n, "dns_suffix"))
            .filter(|s| !s.is_empty())
            .unwrap_or("phub");
        for peer in &requested {
            if peer.get("workspace_id") != Some(&workspace) {
                continue;
            }
            if let Some(label) = labels.primary.get(&store::id(peer.get("_id"))) {
                domains.insert(
                    store::id(peer.get("machine_id")),
                    format!("{label}.{suffix}"),
                );
            }
        }
    }
    Ok(domains)
}
fn user_id(value: &str, message: &str) -> ApiResult<ObjectId> {
    ObjectId::parse_str(value).map_err(|_| ApiError::bad_request(message))
}
fn base(kind: &str, owner: Bson, p: &Params, app: &App) -> ApiResult<(String, Vec<Document>)> {
    let collection = match kind {
        "accounts" => "users",
        "machines" => "machines",
        "connections" => "connections",
        "proxies" => "traffic_routes",
        "groups" => "machine_groups",
        "proxy-groups" => "traffic_routes",
        _ => return Err(ApiError::bad_request("Unknown inventory kind")),
    };
    let mut filter = if kind == "accounts" {
        Document::new()
    } else {
        doc! {"user_id":&owner}
    };
    if kind == "accounts" && p.role != "all" {
        if !["user", "admin"].contains(&p.role.as_str()) {
            return Err(ApiError::bad_request("Invalid account role"));
        }
        filter.insert("role", &p.role);
    }
    if !p.ids.is_empty() {
        let ids = p
            .ids
            .split(',')
            .map(|id| user_id(id, "Invalid inventory ID"))
            .collect::<ApiResult<Vec<_>>>()?;
        if ids.len() > 100 {
            return Err(ApiError::bad_request(
                "At most 100 inventory IDs are supported",
            ));
        }
        filter.insert("_id", doc! {"$in":ids});
    }
    if kind == "machines" {
        filter.insert("deletion_pending", doc! {"$ne":true});
        match p.status.as_str() {
            "enabled" => {
                filter.insert("enabled", doc! {"$ne":false});
            }
            "disabled" => {
                filter.insert("enabled", false);
            }
            "online" | "offline" | "auth_required" => {
                filter.insert("enabled", doc! {"$ne":false});
                let cutoff = bson::DateTime::from_millis(
                    bson::DateTime::now().timestamp_millis() - app.config.machine_online_ttl_millis,
                );
                if p.status == "offline" {
                    filter.insert(
                        "$or",
                        vec![
                            doc! {"last_seen_at":{"$lt":cutoff}},
                            doc! {"last_seen_at":{"$not":{"$type":"date"}}},
                        ],
                    );
                } else {
                    filter.insert("last_seen_at", doc! {"$gte":cutoff});
                    if p.status == "auth_required" {
                        filter.insert("auth_required", true);
                    }
                }
            }
            "all" => {}
            _ => return Err(ApiError::bad_request("Invalid machine status")),
        }
        if !p.group.is_empty() && p.group != "all" {
            let id = user_id(&p.group, "Invalid group")?;
            let groups = doc! {"$or":[{"group_ids":{"$in":[Bson::ObjectId(id),Bson::String(p.group.clone())]}},{"group_id":{"$in":[Bson::ObjectId(id),Bson::String(p.group.clone())]}}]};
            filter = doc! {"$and":[filter,groups]};
        }
    } else if p.status == "enabled" {
        filter.insert("enabled", doc! {"$ne":false});
    } else if p.status == "disabled" {
        filter.insert("enabled", false);
    }
    if kind == "connections" && p.machine != "all" && !p.machine.is_empty() {
        filter.insert("machine_id", user_id(&p.machine, "Invalid machine")?);
    }
    if kind == "proxies" {
        if p.group != "all" {
            if p.group.is_empty() {
                filter = doc! {"$and":[filter,{"$or":[{"group":""},{"group":Bson::Null}]}]};
            } else {
                filter.insert("group", &p.group);
            }
        }
        if !p.machine.is_empty() && p.machine != "all" {
            let linked = if p.machine == "manual" {
                doc! {"$or":[{"target_mode":"manual"},{"bindings.target_mode":"manual"}]}
            } else {
                user_id(&p.machine, "Invalid machine")?;
                doc! {"$or":[{"connection.machine_id":&p.machine},{"bindings.connection.machine_id":&p.machine}]}
            };
            filter = doc! {"$and":[filter,linked]};
        }
        if !p.connection.is_empty() {
            user_id(&p.connection, "Invalid connection")?;
            filter = doc! {"$and":[filter,{"$or":[{"connection.data_id":&p.connection},{"bindings.connection.data_id":&p.connection}]}]};
        }
    }
    let mut pipeline = vec![doc! {"$match":filter}];
    if kind == "accounts" {
        if !p.q.trim().is_empty() {
            for (collection, fields, output) in [
                (
                    "machines",
                    doc! {"name":1,"hostname":1,"local_ip":1,"public_ip":1},
                    "_account_machines",
                ),
                (
                    "connections",
                    doc! {"service_name":1,"external_port":1},
                    "_account_ports",
                ),
            ] {
                pipeline.push(doc! {"$lookup":{"from":collection,"let":{"owner":"$_id"},"pipeline":[{"$match":{"$expr":{"$eq":["$user_id","$$owner"]}}},{"$project":fields}],"as":output}});
            }
        }
        if p.sort == "machines" {
            pipeline.push(account_counts(app));
            pipeline.push(doc! {"$set":{"machine_count":{"$ifNull":[{"$arrayElemAt":["$_account_counts.total",0]},0]}}});
        }
    }
    if kind == "proxy-groups" {
        pipeline.push(doc! {"$group":{"_id":{"$ifNull":["$group",""]},"count":{"$sum":1}}});
        pipeline.push(doc! {"$set":{"name":"$_id"}});
    }
    if kind == "machines" && !p.q.trim().is_empty() {
        pipeline.push(peers(owner.clone()));

        pipeline.push(joined("connections","_id","machine_id",owner.clone(),doc!{"service_name":1,"service_description":1,"internal_port":1,"external_port":1,"internal_ip":1},"_ports"));
    }
    if kind == "connections" {
        pipeline.push(joined("machines","machine_id","_id",owner.clone(),doc!{"name":1,"hostname":1,"hostname_override":1,"client_hostname":1,"enabled":1,"last_seen_at":1,"auth_required":1},"_machines"));
    }
    if !p.q.trim().is_empty() {
        let search:Bson=match kind{
   "accounts"=>doc!{"$concatArrays":[fields(&["name","email","username"]),list_fields("_account_machines",&["name","hostname","local_ip","public_ip"]),list_fields("_account_ports",&["service_name","external_port"])]}.into(),
   "machines"=>doc!{"$concatArrays":[fields(&["name","hostname","hostname_override","client_hostname","local_ip","public_ip"]),{"$ifNull":["$aliases",[]]},list_fields("_ports",&["service_name","service_description","internal_port","external_port","internal_ip"]),list_fields("_peers",&["ip","hostname"])]}.into(),
   "connections"=>doc!{"$concatArrays":[fields(&["service_name","service_description","internal_ip","internal_port","external_port"]),list_fields("_machines",&["name","hostname","hostname_override","client_hostname"])]}.into(),
   "proxies"=>doc!{"$concatArrays":[fields(&["name","description","group","target_url","connection.machine_name","connection.service_name","connection.internal_port","connection.external_port"]),{"$ifNull":["$hosts",[]]},list_fields("bindings",&["label","target_url","connection.machine_name","connection.service_name","connection.internal_port","connection.external_port"])]}.into(),
   _=>fields(&["name"]),
  };
        pipeline.push(doc! {"$set":{"_search_fields":search}});
        pipeline.extend(search_pipeline(&p.q));
    }
    Ok((collection.into(), pipeline))
}
fn quote(c: char) -> String {
    if ".^$*+?()[]{}|\\".contains(c) {
        format!("\\{c}")
    } else {
        c.to_string()
    }
}
fn char_pattern(c: char) -> String {
    match c.to_ascii_lowercase() {
        'a' => "[aàáâãäåā]".into(),
        'e' => "[eèéêëē]".into(),
        'i' => "[iìíîïī]".into(),
        'o' => "[oòóôõöō]".into(),
        'u' => "[uùúûüū]".into(),
        'c' => "[cçćč]".into(),
        'n' => "[nñń]".into(),
        _ => quote(c),
    }
}
/// Exact/prefix/substring precede single-edit word matches. Numeric terms never
/// receive fuzzy matching: a nearby port/IP is a different destination.
pub fn patterns(term: &str) -> (String, Option<String>) {
    use unicode_normalization::UnicodeNormalization;
    let normalized: String = term
        .nfkd()
        .filter(|c| !unicode_normalization::char::is_combining_mark(*c))
        .collect();
    let chars: Vec<_> = normalized.chars().collect();
    let literal = chars.iter().map(|&c| char_pattern(c)).collect::<String>();
    if chars.len() < 4 || chars.len() > 32 || !chars.iter().any(|c| c.is_alphabetic()) {
        return (literal, None);
    }
    let parts: Vec<_> = chars.iter().map(|&c| char_pattern(c)).collect();
    let mut alternatives = vec![literal.clone()];
    for i in 0..parts.len() {
        let mut deletion = parts.clone();
        deletion.remove(i);
        alternatives.push(deletion.join(""));
        let mut substitution = parts.clone();
        substitution[i] = "[\\p{L}\\p{N}]".into();
        alternatives.push(substitution.join(""));
        if i + 1 < parts.len() {
            let mut swap = parts.clone();
            swap.swap(i, i + 1);
            alternatives.push(swap.join(""));
        }
    }
    for i in 0..=parts.len() {
        let mut insertion = parts.clone();
        insertion.insert(i, "[\\p{L}\\p{N}]".into());
        alternatives.push(insertion.join(""));
    }
    (
        literal,
        Some(format!(
            "(?:^|[^\\p{{L}}\\p{{N}}])(?:{})(?:$|[^\\p{{L}}\\p{{N}}])",
            alternatives.join("|")
        )),
    )
}
fn any_match(regex: String) -> Bson {
    doc!{"$anyElementTrue":[{"$map":{"input":"$_search_fields","as":"field","in":{"$regexMatch":{"input":{"$convert":{"input":"$$field","to":"string","onError":"","onNull":""}},"regex":regex,"options":"i"}}}}]}.into()
}
pub(crate) fn search_pipeline(query: &str) -> Vec<Document> {
    let scores:Vec<Bson>=query.split_whitespace().map(|term|{let(literal,fuzzy)=patterns(term);let last:Bson=fuzzy.map_or(Bson::Int32(4),|p|doc!{"$cond":[any_match(p),3,4]}.into());doc!{"$cond":[any_match(format!("^{literal}$")),0,{"$cond":[any_match(format!("^{literal}")),1,{"$cond":[any_match(literal),2,last]}]}]}.into()}).collect();
    vec![
        doc! {"$set":{"_scores":scores}},
        doc! {"$match":{"$expr":{"$allElementsTrue":[{"$map":{"input":"$_scores","as":"score","in":{"$lt":["$$score",4]}}}]}}},
        doc! {"$set":{"_score":{"$sum":"$_scores"}}},
    ]
}
fn sorting(p: &Params, kind: &str) -> ApiResult<Document> {
    let mut sort = Document::new();
    if !p.q.trim().is_empty() && p.sort == "name" {
        sort.insert("_score", 1);
    }
    match p.sort.as_str() {
        "name" | "name-desc" => {
            sort.insert(
                if kind == "connections" {
                    "service_name"
                } else {
                    "name"
                },
                if p.sort == "name-desc" { -1 } else { 1 },
            );
        }
        "newest" => {
            sort.insert("created_at", -1);
        }
        "oldest" => {
            sort.insert("created_at", 1);
        }
        "machines" if kind == "accounts" => {
            sort.insert("machine_count", -1);
            sort.insert("name", 1);
        }
        "updated" => {
            sort.insert("updated_at", -1);
        }
        "status" => {
            sort.insert("enabled", -1);
            sort.insert("name", 1);
        }
        _ => return Err(ApiError::bad_request("Invalid inventory sort")),
    };
    sort.insert("_id", 1);
    Ok(sort)
}
async fn page(
    State(app): State<Arc<App>>,
    Path(kind): Path<String>,
    Query(params): Query<Params>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    params.validate()?;
    let user = auth::current_user(&app, &headers).await?;
    if let Some(kind) = kind.strip_prefix("access-") {
        return crate::access_inventory::page(app, kind, &params, &headers, &user).await;
    }
    let is_admin = store::string(&user, "role") == "admin";
    if (kind == "accounts" || !params.account.is_empty()) && !is_admin {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Admin access required",
        ));
    }
    let owner = if params.account.is_empty() {
        user.get("_id")
            .cloned()
            .ok_or_else(ApiError::unauthenticated)?
    } else {
        Bson::ObjectId(user_id(&params.account, "Invalid account ID")?)
    };
    let traffic_mode = kind == "traffic";
    let kind = if traffic_mode {
        "connections".to_owned()
    } else {
        kind
    };
    let (collection, mut pipeline) = base(&kind, owner.clone(), &params, &app)?;
    let traffic_sort =
        ["traffic", "incoming", "outgoing", "blocked"].contains(&params.sort.as_str());
    let snapshot = if traffic_sort || traffic_mode {
        Some(if traffic_mode && !params.ids.is_empty() {
            crate::inventory_traffic::connections(
                &app,
                &owner,
                params
                    .ids
                    .split(',')
                    .map(|id| user_id(id, "Invalid connection ID"))
                    .collect::<ApiResult<Vec<_>>>()?,
            )
            .await?
        } else if traffic_mode && !["", "all"].contains(&params.machine.as_str()) {
            crate::inventory_traffic::machines(
                &app,
                &owner,
                vec![user_id(&params.machine, "Invalid machine ID")?],
            )
            .await?
        } else {
            crate::inventory_traffic::snapshot(&app, &owner).await?
        })
    } else {
        None
    };
    let mut combined = Vec::new();
    let mut traffic_revision = String::new();
    let mut watermark = None;
    let now = bson::DateTime::now().timestamp_millis() as f64 / 1000.;
    let sort = if let Some(snapshot) = snapshot.as_ref() {
        let mut candidates = pipeline.clone();
        candidates.push(doc! {"$sort":{"name":1,"service_name":1,"_id":1}});
        candidates.push(doc! {"$project":{"_id":1,"connection.data_id":1}});
        let mut records = app
            .collection(&collection)
            .aggregate(candidates)
            .collation(
                Collation::builder()
                    .locale("en")
                    .strength(CollationStrength::Primary)
                    .numeric_ordering(true)
                    .build(),
            )
            .max_time(Duration::from_secs(3))
            .await?
            .try_collect::<Vec<Document>>()
            .await?;
        if traffic_mode {
            let ids = records
                .iter()
                .map(|row| store::id(row.get("_id")))
                .collect::<Vec<_>>();
            traffic_revision = snapshot.revision(ids.iter().map(String::as_str));
            watermark =
                snapshot.watermark(ids.iter().map(String::as_str), params.seconds as f64, now);
            combined = crate::inventory_traffic::aggregate(
                records
                    .iter()
                    .filter_map(|record| snapshot.ports.get(&store::id(record.get("_id"))))
                    .flatten()
                    .copied(),
            );
        }
        if traffic_sort {
            let metrics = records
                .iter()
                .map(|record| {
                    (
                        store::id(record.get("_id")),
                        snapshot.metric(&kind, record, &params.sort, params.seconds as f64, now),
                    )
                })
                .collect::<std::collections::HashMap<_, _>>();
            records.sort_by(|a, b| {
                metrics[&store::id(b.get("_id"))].total_cmp(&metrics[&store::id(a.get("_id"))])
            });
            let ranked = records
                .iter()
                .filter_map(|record| record.get("_id").cloned())
                .collect::<Vec<_>>();
            pipeline.push(doc! {"$set":{"_traffic_rank":{"$indexOfArray":[ranked,"$_id"]}}});
            doc! {"_traffic_rank":1,"_id":1}
        } else {
            sorting(&params, &kind)?
        }
    } else {
        sorting(&params, &kind)?
    };
    let mut data = vec![
        doc! {"$sort":sort},
        doc! {"$skip":((params.page-1)*params.page_size) as i64},
        doc! {"$limit":params.page_size as i64},
    ];
    if kind == "accounts" {
        data.push(doc! {"$lookup":{"from":"connections","let":{"owner":"$_id"},"pipeline":[{"$match":{"$expr":{"$eq":["$user_id","$$owner"]}}},{"$count":"total"}],"as":"_account_ports_count"}});
    }
    if kind == "accounts" && params.sort != "machines" {
        data.push(account_counts(&app));
    }
    if kind == "machines" && params.q.trim().is_empty() && !params.options {
        data.push(peers(owner.clone()));
    }
    if kind == "proxies" {
        data.push(doc! {"$set":{"bindings_count":{"$cond":[{"$isArray":"$bindings"},{"$size":"$bindings"},1]}}});
        if !params.detail {
            data.push(doc! {"$set":{"bindings":{"$cond":[{"$isArray":"$bindings"},{"$slice":["$bindings",2]},Bson::Null]}}});
        }
    }
    if kind == "connections" && !params.options {
        let lookup = doc! {"from":"traffic_routes","let":{"connection":{"$toString":"$_id"}},"pipeline":[{"$match":{"user_id":&owner,"$expr":{"$or":[{"$eq":["$connection.data_id","$$connection"]},{"$in":["$$connection",{"$map":{"input":{"$ifNull":["$bindings",[]]},"as":"binding","in":"$$binding.connection.data_id"}}]}]}}},{"$project":{"hosts":1,"entry_points":1,"name":1}},{"$sort":{"_id":1}},{"$limit":2}],"as":"_linked_proxies"};
        data.push(doc! {"$lookup":lookup});
    }
    if kind == "groups" && !params.options {
        data.push(doc! {"$lookup":{"from":"machines","let":{"group":"$_id","text":{"$toString":"$_id"}},"pipeline":[{"$match":{"user_id":&owner,"deletion_pending":{"$ne":true},"$expr":{"$or":[{"$in":["$$group",{"$ifNull":["$group_ids",[]]}]},{"$in":["$$text",{"$ifNull":["$group_ids",[]]}]},{"$eq":["$group_id","$$group"]},{"$eq":["$group_id","$$text"]}]}}},{"$count":"count"}],"as":"_members"}});
    }
    if kind == "machines" && !params.options {
        data.push(doc! {"$lookup":{"from":"machine_groups","let":{"groups":{"$ifNull":["$group_ids",["$group_id"]]}},"pipeline":[{"$match":{"user_id":&owner,"$expr":{"$or":[{"$in":["$_id","$$groups"]},{"$in":[{"$toString":"$_id"},"$$groups"]}]}}},{"$project":{"name":1}}],"as":"_groups"}});
        let mut lookup = joined(
            "connections",
            "_id",
            "machine_id",
            owner.clone(),
            doc! {"user_id":1,"machine_id":1,"service_name":1,"service_description":1,"internal_ip":1,"internal_port":1,"external_port":1,"external_bind_ip":1,"enabled":1,"temporary":1,"auto_refresh_enabled":1,"auto_refresh_interval_minutes":1,"auto_refreshed_at":1,"auto_refresh_next_at":1,"firewall":1,"public_access":1,"managed_by":1,"lease_expires_at":1,"created_at":1,"updated_at":1},
            "_page_ports",
        );
        let stages = lookup
            .get_document_mut("$lookup")
            .unwrap()
            .get_array_mut("pipeline")
            .unwrap();
        stages.push(doc! {"$sort":{"external_port":1,"_id":1}}.into());
        stages.push(doc! {"$limit":10}.into());
        data.push(lookup);
        let mut counts = joined(
            "connections",
            "_id",
            "machine_id",
            owner.clone(),
            doc! {"enabled":1},
            "_port_counts",
        );
        counts.get_document_mut("$lookup").unwrap().get_array_mut("pipeline").unwrap().push(doc!{"$group":{"_id":Bson::Null,"total":{"$sum":1},"enabled":{"$sum":{"$cond":[{"$eq":["$enabled",false]},0,1]}}}}.into());
        data.push(counts);
    }
    pipeline.push(doc! {"$facet":{"data":data,"total":[{"$count":"count"}]}});
    let result = app
        .collection(&collection)
        .aggregate(pipeline)
        .collation(
            Collation::builder()
                .locale("en")
                .strength(CollationStrength::Primary)
                .numeric_ordering(true)
                .build(),
        )
        .max_time(Duration::from_secs(3))
        .await?
        .try_next()
        .await?
        .unwrap_or_default();
    let total = result
        .get_array("total")
        .ok()
        .and_then(|a| a.first())
        .and_then(Bson::as_document)
        .and_then(|d| d.get("count"))
        .map(store::json)
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let domains = if kind == "machines" && !params.options {
        private_domains(&app, &result).await?
    } else {
        Default::default()
    };
    let reset = traffic_mode
        && !params.scope_revision.is_empty()
        && params.scope_revision != traffic_revision;
    let aggregate_since = if reset { 0 } else { params.since };
    let mut rows = Vec::new();
    let mut connections = Vec::new();
    for record in result
        .get_array("data")
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Bson::as_document)
    {
        let mut value = match kind.as_str() {
            "accounts" => {
                let counts = record
                    .get_array("_account_counts")
                    .ok()
                    .and_then(|rows| rows.first())
                    .and_then(Bson::as_document);
                let email = store::string(record, "email");
                json!({"user":{"id":store::id(record.get("_id")),"name":store::string(record,"name"),"email":if email.is_empty(){store::string(record,"username")}else{email},"role":if store::string(record,"role").is_empty(){"user"}else{store::string(record,"role")},"deleting":record.contains_key("account_deletion"),"created_at":store::field(record,"created_at")},"machine_count":counts.map(|c|store::field(c,"total")).unwrap_or(json!(0)),"online_count":counts.map(|c|store::field(c,"online")).unwrap_or(json!(0)),"port_count":record.get_array("_account_ports_count").ok().and_then(|rows|rows.first()).and_then(Bson::as_document).map(|row|store::field(row,"total")).unwrap_or(json!(0))})
            }
            "machines" => inventory::machine(&app, record),
            "connections" => inventory::connection(
                &app,
                record,
                record
                    .get_array("_machines")
                    .ok()
                    .and_then(|a| a.first())
                    .and_then(Bson::as_document),
            ),
            "proxies" => crate::domain::traffic_routes::serialize(record),
            _ => {
                json!({"_id":store::id(record.get("_id")),"name":store::string(record,"name"),"created_at":store::field(record,"created_at")})
            }
        };
        if kind == "proxies" {
            value["bindings_count"] = store::field(record, "bindings_count");
            value["bindings_truncated"] = json!(record
                .get_array("bindings")
                .is_ok_and(|bindings| value["bindings_count"].as_u64().unwrap_or(0)
                    > bindings.len() as u64));
        }
        if kind == "connections" && !params.options {
            value["linked_proxies"] = json!(record.get_array("_linked_proxies").ok().into_iter().flatten().filter_map(Bson::as_document).map(|p|json!({"_id":store::id(p.get("_id")),"name":store::string(p,"name"),"hosts":store::field(p,"hosts"),"entry_points":store::field(p,"entry_points")})).collect::<Vec<_>>());
        }
        if kind == "groups" {
            value["machineCount"] = record
                .get_array("_members")
                .ok()
                .and_then(|rows| rows.first())
                .and_then(Bson::as_document)
                .map(|row| store::field(row, "count"))
                .unwrap_or(json!(0));
        }
        if kind == "machines" {
            value["group_labels"] = json!(record
                .get_array("_groups")
                .ok()
                .into_iter()
                .flatten()
                .filter_map(Bson::as_document)
                .map(|g| json!({"_id":store::id(g.get("_id")),"name":store::string(g,"name")}))
                .collect::<Vec<_>>());
            value["default_private_domain"] = json!(domains
                .get(&store::id(record.get("_id")))
                .cloned()
                .unwrap_or_default());
            let ips = if record.get_bool("private_owner_revoked") == Ok(true) {
                Vec::new()
            } else {
                record
                    .get_array("_peers")
                    .ok()
                    .into_iter()
                    .flatten()
                    .filter_map(Bson::as_document)
                    .filter_map(|p| store::string(p, "ip").parse::<std::net::Ipv4Addr>().ok())
                    .filter(std::net::Ipv4Addr::is_private)
                    .map(|ip| ip.to_string())
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>()
            };
            value["private_ips"] = json!(ips);
            let detail = record
                .get_array("_port_counts")
                .ok()
                .and_then(|a| a.first())
                .and_then(Bson::as_document);
            let ports: Vec<_> = record
                .get_array("_page_ports")
                .ok()
                .into_iter()
                .flatten()
                .filter_map(Bson::as_document)
                .collect();
            let count = |name: &str| {
                detail
                    .and_then(|d| d.get(name))
                    .map(store::json)
                    .unwrap_or(json!(0))
            };
            value["num_ports"] = count("enabled");
            value["ports_total"] = count("total");
            value["ports_truncated"] =
                json!(value["ports_total"].as_u64().unwrap_or(0) > ports.len() as u64);
            if !params.options {
                for port in ports {
                    connections.push(inventory::connection(&app, port, Some(record)));
                }
            }
        }
        if params.options {
            value = options(&kind, &value);
        }
        if traffic_mode {
            let id = store::id(record.get("_id"));
            let known = !reset
                && (params.row_cursor(&id).is_some()
                    || params.known.split(',').any(|known| known == id));
            let since = if reset {
                0
            } else {
                params.row_cursor(&id).unwrap_or(params.since)
            };
            let samples = if params.expanded == id {
                let rows = crate::inventory_traffic::expanded(&app, &owner, record).await?;
                rows.iter()
                    .filter(|sample| {
                        let time = sample["timestamp"].as_u64().unwrap_or(0);
                        (!known || time >= since)
                            && time as f64 > now - params.seconds as f64
                            && time as f64 <= now + 1.
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            } else {
                snapshot
                    .as_ref()
                    .and_then(|snapshot| snapshot.ports.get(&id))
                    .into_iter()
                    .flatten()
                    .filter(|sample| {
                        (!known || sample.timestamp >= since)
                            && sample.timestamp as f64 > now - params.seconds as f64
                            && sample.timestamp as f64 <= now + 1.
                    })
                    .map(|sample| json!(sample))
                    .collect::<Vec<_>>()
            };
            value = json!({"connection":value,"traffic":samples});
        }
        rows.push(value);
    }
    let mut body = json!({"data":rows,"connections":connections,"pagination":{"page":params.page,"page_size":params.page_size,"total":total,"pages":total.div_ceil(params.page_size).max(1)}});
    if traffic_mode {
        let series = combined
            .iter()
            .filter(|sample| {
                sample.timestamp as f64 > now - params.seconds as f64
                    && sample.timestamp as f64 <= now + 1.
            })
            .copied()
            .collect::<Vec<_>>();
        let delta = crate::inventory_traffic::series_delta(
            &app,
            format!(
                "{}:{traffic_revision}:aggregate:{}",
                store::id(Some(&owner)),
                params.seconds
            ),
            if reset { "" } else { &params.aggregate_token },
            &series,
        )
        .await;
        let legacy = params.aggregate_token.is_empty() && params.since > 0 && !reset;
        body["aggregate"] = json!(delta
            .points
            .iter()
            .filter(|sample| !legacy || sample.timestamp >= aggregate_since)
            .collect::<Vec<_>>());
        body["aggregate_token"] = json!(delta.token);
        body["aggregate_removed"] = json!(delta.removed);
        body["aggregate_replace"] = json!(delta.replace && !legacy);
        body["cursor"] = json!(watermark.unwrap_or(aggregate_since).max(aggregate_since));
        body["scope_revision"] = json!(traffic_revision);
        body["reset"] = json!(reset);
    }
    conditional(&headers, body)
}
fn account_counts(app: &App) -> Document {
    let cutoff = bson::DateTime::from_millis(
        bson::DateTime::now().timestamp_millis() - app.config.machine_online_ttl_millis,
    );
    doc! {"$lookup":{"from":"machines","let":{"owner":"$_id"},"pipeline":[{"$match":{"deletion_pending":{"$ne":true},"$expr":{"$eq":["$user_id","$$owner"]}}},{"$group":{"_id":Bson::Null,"total":{"$sum":1},"online":{"$sum":{"$cond":[{"$and":[{"$ne":["$enabled",false]},{"$ne":["$auth_required",true]},{"$gte":[{"$ifNull":["$last_seen_at",bson::DateTime::from_millis(0)]},cutoff]}]},1,0]}}}}],"as":"_account_counts"}}
}
fn options(kind: &str, row: &Value) -> Value {
    let keys: &[&str] = match kind {
        "machines" => &[
            "_id",
            "name",
            "hostname",
            "enabled",
            "connection_status",
            "group_ids",
        ],
        "connections" => &[
            "_id",
            "machine_id",
            "machine_name",
            "service_name",
            "internal_ip",
            "internal_port",
            "external_port",
            "enabled",
        ],
        _ => &["_id", "name", "group", "hosts"],
    };
    let mut out = serde_json::Map::new();
    for key in keys {
        if let Some(v) = row.get(*key) {
            out.insert((*key).into(), v.clone());
        }
    }
    Value::Object(out)
}
pub fn conditional(headers: &HeaderMap, body: Value) -> ApiResult<Response> {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(&body)
        .map_err(|_| ApiError::bad_request("Invalid inventory response"))?;
    let etag = format!("\"{:x}\"", Sha256::digest(&bytes));
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|h| h.to_str().ok())
        == Some(etag.as_str())
    {
        return Ok((
            StatusCode::NOT_MODIFIED,
            [
                (header::ETAG, etag),
                (header::CACHE_CONTROL, "private, no-cache".into()),
            ],
        )
            .into_response());
    }
    Ok((
        [
            (header::ETAG, etag),
            (header::CACHE_CONTROL, "private, no-cache".into()),
        ],
        Json(body),
    )
        .into_response())
}

/// Install only additive indexes; no inventory records or user configuration
/// are rewritten. Both browsing and correlated lookups start with owner scope.
pub async fn ensure_indexes(app: &App) -> ApiResult<()> {
    use mongodb::{options::IndexOptions, IndexModel};
    for (collection, keys) in [
        ("users", doc! {"name":1,"_id":1}),
        ("machines", doc! {"user_id":1,"name":1,"_id":1}),
        (
            "connections",
            doc! {"user_id":1,"machine_id":1,"external_port":1,"_id":1},
        ),
        ("traffic_routes", doc! {"user_id":1,"name":1,"_id":1}),
        ("machine_groups", doc! {"user_id":1,"name":1,"_id":1}),
    ] {
        app.collection(collection)
            .create_index(
                IndexModel::builder()
                    .keys(keys)
                    .options(
                        IndexOptions::builder()
                            .name("porthub_inventory_owner_page_v1".to_owned())
                            .collation(
                                Collation::builder()
                                    .locale("en")
                                    .strength(CollationStrength::Primary)
                                    .numeric_ordering(true)
                                    .build(),
                            )
                            .build(),
                    )
                    .build(),
            )
            .await?;
    }
    Ok(())
}

async fn status(
    State(app): State<Arc<App>>,
    Query(query): Query<std::collections::HashMap<String, String>>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let user = auth::current_user(&app, &headers).await?;
    let raw = query.get("ids").map(String::as_str).unwrap_or("");
    let ids = raw
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| user_id(s, "Invalid machine ID"))
        .collect::<ApiResult<Vec<_>>>()?;
    if ids.len() > 100 {
        return Err(ApiError::bad_request(
            "Status requests support at most 100 machine IDs",
        ));
    }
    let machines = app
        .collection("machines")
        .find(doc! {"_id":{"$in":ids},"user_id":user.get("_id"),"deletion_pending":{"$ne":true}})
        .await?
        .try_collect::<Vec<Document>>()
        .await?;
    let rows = machines
        .iter()
        .map(|machine| {
            let full = inventory::machine(&app, machine);
            let mut light = serde_json::Map::new();
            for key in [
                "_id",
                "name",
                "hostname",
                "enabled",
                "auth_required",
                "connection_status",
                "is_active",
                "last_seen_at",
                "client_version",
                "latest_client_version",
                "client_update_available",
                "client_update_requested",
            ] {
                light.insert(key.into(), full[key].clone());
            }
            Value::Object(light)
        })
        .collect::<Vec<_>>();
    conditional(&headers, json!({"data":rows}))
}

/// Counts for the workspace header/dashboard without downloading inventories.
async fn summary(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Response> {
    let user = auth::current_user(&app, &headers).await?;
    let owner = user
        .get("_id")
        .cloned()
        .ok_or_else(ApiError::unauthenticated)?;
    let cutoff = bson::DateTime::from_millis(
        bson::DateTime::now().timestamp_millis() - app.config.machine_online_ttl_millis,
    );
    let pipeline = vec![
        doc! {"$match":{"user_id":&owner,"deletion_pending":{"$ne":true}}},
        doc! {"$group":{"_id":{"$cond":[{"$eq":["$enabled",false]},"disabled",{"$cond":[{"$lt":[{"$ifNull":["$last_seen_at",bson::DateTime::from_millis(0)]},cutoff]},"offline",{"$cond":[{"$eq":["$auth_required",true]},"auth_required","online"]}]}]},"count":{"$sum":1}}},
    ];
    let counts = app
        .collection("machines")
        .aggregate(pipeline)
        .await?
        .try_collect::<Vec<Document>>()
        .await?;
    let mut machines = json!({"total":0,"online":0,"offline":0,"disabled":0,"auth_required":0});
    let mut total = 0u64;
    for count in counts {
        let key = store::string(&count, "_id");
        let value = store::field(&count, "count").as_u64().unwrap_or(0);
        machines[key] = json!(value);
        total += value;
    }
    machines["total"] = json!(total);
    let ports = app
        .collection("connections")
        .count_documents(doc! {"user_id":&owner})
        .await?;
    let proxies = app
        .collection("traffic_routes")
        .count_documents(doc! {"user_id":&owner})
        .await?;
    conditional(
        &headers,
        json!({"data":{"machines":machines,"ports":ports,"proxies":proxies}}),
    )
}

async fn machine_traffic(
    State(app): State<Arc<App>>,
    Query(params): Query<Params>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    params.validate()?;
    let user = auth::current_user(&app, &headers).await?;
    let owner = user
        .get("_id")
        .cloned()
        .ok_or_else(ApiError::unauthenticated)?;
    let ids = params
        .ids
        .split(',')
        .filter(|id| !id.is_empty())
        .map(|id| user_id(id, "Invalid machine ID"))
        .collect::<ApiResult<Vec<_>>>()?;
    if ids.len() > 100 {
        return Err(ApiError::bad_request("At most 100 machines are supported"));
    }
    let machines = app
        .collection("machines")
        .find(doc! {"user_id":&owner,"_id":{"$in":ids},"deletion_pending":{"$ne":true}})
        .projection(doc! {"_id":1})
        .await?
        .try_collect::<Vec<_>>()
        .await?;
    let snapshot = crate::inventory_traffic::machines(
        &app,
        &owner,
        machines
            .iter()
            .filter_map(|row| row.get_object_id("_id").ok())
            .collect(),
    )
    .await?;
    let now = bson::DateTime::now().timestamp_millis() as f64 / 1000.;
    let connection_ids = machines
        .iter()
        .flat_map(|machine| {
            snapshot
                .machine_ports
                .get(&store::id(machine.get("_id")))
                .into_iter()
                .flatten()
        })
        .map(String::as_str)
        .collect::<Vec<_>>();
    let revision = snapshot.revision(connection_ids.iter().copied());
    let reset = !params.scope_revision.is_empty() && params.scope_revision != revision;
    let mut cursor = if reset { 0 } else { params.since };
    let mut rows = Vec::new();
    for machine in machines {
        let id = store::id(machine.get("_id"));
        let samples = crate::inventory_traffic::aggregate(
            snapshot
                .machine_ports
                .get(&id)
                .into_iter()
                .flatten()
                .filter_map(|id| snapshot.ports.get(id))
                .flatten()
                .copied()
                .filter(|sample| {
                    sample.timestamp as f64 > now - params.seconds as f64
                        && sample.timestamp as f64 <= now + 1.
                }),
        );
        cursor = cursor.max(samples.last().map(|sample| sample.timestamp).unwrap_or(0));
        let delta = crate::inventory_traffic::series_delta(
            &app,
            format!(
                "{}:{revision}:machine:{id}:{}",
                store::id(Some(&owner)),
                params.seconds
            ),
            if reset { "" } else { params.row_token(&id) },
            &samples,
        )
        .await;
        rows.push(json!({"connection":{"_id":id},"traffic":delta.points,"token":delta.token,"removed":delta.removed,"replace":delta.replace}));
    }
    conditional(
        &headers,
        json!({"data":rows,"aggregate":[],"cursor":cursor,"scope_revision":revision,"reset":reset,"pagination":{"page":1,"page_size":rows.len(),"total":rows.len(),"pages":1}}),
    )
}
