use crate::{
    domain::{
        enrollment, private_names, private_policy,
        private_sync::{self, Signal},
        workspaces::token_digest,
    },
    error::{ApiError, ApiResult},
    input::ApiBody,
    store, App,
};
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use futures_util::TryStreamExt;
use mongodb::{
    bson::{doc, oid::ObjectId, DateTime, Document},
    options::{IndexOptions, ReturnDocument},
    IndexModel,
};
use regex::Regex;
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, LazyLock},
    time::Duration,
};

pub fn router() -> Router<Arc<App>> {
    Router::new().route("/api/access/private/sync", post(sync))
        .route("/api/access/private/changes", post(changes))
}
const PAIR_REPLY_BYTES:usize=2*1024*1024;
fn push_pair_response(output:&mut Vec<Value>,bytes:&mut usize,value:Value){
    let length=serde_json::to_vec(&value).map(|v|v.len()).unwrap_or(usize::MAX);
    let value=if bytes.saturating_add(length)>PAIR_REPLY_BYTES-16384 {
        json!({"query":value["query"],"status":"busy"})
    }else{value};
    *bytes+=serde_json::to_vec(&value).expect("typed pair response").len();output.push(value);
}
fn forbidden(message: &str) -> ApiError {
    ApiError::new(StatusCode::FORBIDDEN, message)
}
async fn indexes(app: &App) -> ApiResult<()> {
    app.private_initialized
        .get_or_try_init(|| async {
            app.collection("private_signals")
                .create_index(
                    IndexModel::builder()
                        .keys(doc! {"expires_at":1})
                        .options(IndexOptions::builder().expire_after(Duration::ZERO).build())
                        .build(),
                )
                .await?;
            app.collection("private_signals")
                .create_index(
                    IndexModel::builder()
                        .keys(doc! {"to":1,"target_instance":1,"expires_at":1})
                        .build(),
                )
                .await?;
            Ok::<_, ApiError>(())
        })
        .await?;
    Ok(())
}
pub(crate) async fn active(
    app: &App,
    owner: ObjectId,
) -> ApiResult<(Vec<Document>, HashMap<String, Document>)> {
    active_matching(app, owner, None).await
}
/// Same current ownership predicate as full sync, but bounded to report targets.
pub(crate) async fn active_report_peers(
    app: &App,
    owner: ObjectId,
    ids: &[String],
) -> ApiResult<Vec<Document>> {
    if ids.len() > porthub_mesh::traffic_report::MAX_ROWS + 1 {
        return Err(ApiError::bad_request("Too many private traffic peers"));
    }
    if ids.is_empty() { return Ok(Vec::new()); }
    Ok(active_matching(app, owner, Some(ids)).await?.0)
}
pub(crate) async fn active_matching(
    app: &App,
    owner: ObjectId,
    selected: Option<&[String]>,
) -> ApiResult<(Vec<Document>, HashMap<String, Document>)> {
    // Preserve the legacy full inventory's early retirement exit and DB filter.
    let full_retired = if selected.is_none() {
        let retired = crate::account_delete::retiring_owners(app).await?;
        if retired.contains(&mongodb::bson::Bson::ObjectId(owner)) { return Ok((Vec::new(), HashMap::new())); }
        Some(retired)
    } else { None };
    let mut filter = doc! {"workspace_id":owner,"enabled":true};
    if let Some(retired) = &full_retired { filter.insert("owner_id",doc! {"$nin":retired}); }
    if let Some(ids) = selected { filter.insert("_id", doc! {"$in": ids}); }
    let peers: Vec<Document> = app
        .collection("private_peers")
        .find(filter)
        .await?
        .try_collect()
        .await?;
    let retired = if selected.is_some() {
        let mut owners: Vec<_> = peers.iter().filter_map(|p|p.get("owner_id").cloned()).collect();
        owners.push(mongodb::bson::Bson::ObjectId(owner));
        let owners = crate::account_delete::identity_aliases(&owners);
        crate::account_delete::retiring_owners_among(app,&owners).await?
    } else { full_retired.expect("full inventory read above") };
    if retired.contains(&mongodb::bson::Bson::ObjectId(owner)) { return Ok((Vec::new(),HashMap::new())); }
    let peers: Vec<_> = peers.into_iter().filter(|peer|!peer.get("owner_id").is_some_and(|id|retired.contains(id))).collect();
    let ids: Vec<_> = peers
        .iter()
        .filter_map(|p| p.get("machine_id").cloned())
        .collect();
    let machines:Vec<Document>=app.collection("machines").find(doc!{"_id":{"$in":ids},"enabled":{"$ne":false},"deletion_pending":{"$ne":true},"private_owner_revoked":{"$ne":true}})
        .projection(doc!{"user_id":1,"private_owner_id":1,"private_owner_revoked":1,"kind":1,"name":1,"hostname":1,"enabled":1,"group_ids":1,"group_id":1}).await?.try_collect().await?;
    let member_filter = if selected.is_some() {
        let owners: Vec<_> = peers.iter().filter_map(|p|p.get("owner_id").cloned()).collect();
        let owners = crate::account_delete::identity_aliases(&owners);
        doc! {"workspace_id":owner,"role":{"$in":["member","admin"]},"user_id":{"$in":owners}}
    } else { doc! {"workspace_id":owner,"role":{"$in":["member","admin"]}} };
    let members: Vec<Document> = app
        .collection("workspace_members")
        .find(member_filter)
        .projection(doc! {"user_id":1})
        .await?
        .try_collect()
        .await?;
    let mut valid = HashSet::from([owner.to_hex()]);
    valid.extend(members.iter().map(|m| store::id(m.get("user_id"))));
    let inventory: HashMap<_, _> = machines
        .into_iter()
        .map(|m| (store::id(m.get("_id")), m))
        .collect();
    let peers: Vec<Document> = peers
        .into_iter()
        .filter(|p| {
            valid.contains(&store::id(p.get("owner_id")))
                && inventory
                    .get(&store::id(p.get("machine_id")))
                    .is_some_and(|m| m.get("user_id") == p.get("owner_id"))
        })
        .collect();
    let mut authorized=Vec::new();
    for peer in peers { if super::virtual_hosts::parent_valid(app,&peer).await? { authorized.push(peer); } }
    Ok((authorized, inventory))
}
static FINGERPRINTS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^a=fingerprint:sha-256 ([^\r\n]+)").unwrap());
static CANDIDATES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^a=candidate:[^\r\n]+").unwrap());
pub fn validate_signal(
    source: &str,
    target: &str,
    signal: &Signal,
    fingerprint: &str,
) -> ApiResult<()> {
    if signal.description.r#type == "candidate" {
        if signal.description.sdp.len() > 4096
            || CANDIDATES.find_iter(&signal.description.sdp).count() != 1
        {
            return Err(ApiError::bad_request("Invalid ICE candidate"));
        }
    } else if (signal.description.r#type == "offer") != (source < target) {
        return Err(ApiError::bad_request("Invalid peer negotiation direction"));
    }
    let mut matches = FINGERPRINTS
        .captures_iter(&signal.description.sdp)
        .peekable();
    if matches.peek().is_none() || matches.any(|m| m[1].to_ascii_uppercase() != fingerprint) {
        return Err(ApiError::bad_request(
            "Signaling certificate does not match the enrolled client",
        ));
    }
    Ok(())
}

// These independent random revisions form an opaque change token, never a credential.
fn notification_cursor(workspace: uuid::Uuid, peer: uuid::Uuid) -> uuid::Uuid {
    uuid::Uuid::from_u128(workspace.as_u128() ^ peer.as_u128())
}

async fn changes(State(app): State<Arc<App>>, ApiBody(raw): ApiBody) -> ApiResult<Response> {
    #[derive(serde::Deserialize)]
    struct Request { peer_id: String, token: String, instance: String, since: String }
    let r: Request = serde_json::from_value(raw).map_err(|_| ApiError::bad_request("Invalid private change cursor"))?;
    if r.peer_id.len()>128 || r.token.len()>256 || r.instance.len()>128 { return Err(ApiError::bad_request("Invalid peer")); }
    let since = uuid::Uuid::parse_str(&r.since).map_err(|_|ApiError::bad_request("Invalid private change cursor"))?;
    let hash = token_digest(&r.token);
    let owner = app.private_relay.change_workspace(&r.peer_id, &hash, &r.instance).ok_or_else(|| forbidden("Private sync required"))?;
    let busy = || ApiError::new(StatusCode::TOO_MANY_REQUESTS, "Change watcher busy");
    let _permit = app.private_changes.admit(&r.peer_id).ok_or_else(busy)?;
    let mut signal = app.private_changes.subscribe(owner).ok_or_else(busy)?;
    let mut peer_signal = app.private_changes.subscribe_peer(&r.peer_id).ok_or_else(busy)?;
    if notification_cursor(*signal.borrow_and_update(), *peer_signal.borrow_and_update()) == since {
        tokio::select! {
            _ = signal.changed() => {},
            _ = peer_signal.changed() => {},
            _ = tokio::time::sleep(Duration::from_secs(25)) => {},
        }
    }
    if app.private_relay.change_workspace(&r.peer_id, &hash, &r.instance) != Some(owner) {return Err(forbidden("Private sync required"));}
    let current = notification_cursor(*signal.borrow(), *peer_signal.borrow());
    Ok(([(header::CACHE_CONTROL,"no-store")], Json(json!({"cursor":current.to_string()}))).into_response())
}
async fn sync(State(app): State<Arc<App>>, ApiBody(raw): ApiBody) -> ApiResult<Response> {
    let _lifecycle=app.account_lifecycle.read().await;
    let traffic=raw.get("traffic").cloned().map(serde_json::from_value::<porthub_mesh::traffic_report::Report>);
    let wants_continuity=raw.get("tcp_continuity").and_then(Value::as_u64)==Some(1);
    let raw_watch=raw.get("watch_changes").and_then(Value::as_bool)==Some(true);
    let input=private_sync::parse(raw)?;let hash=token_digest(&input.token);
    let observed=app.private_relay.admission_snapshot(&input.peer_id,&hash,&input.instance);
    let filter=doc!{"_id":&input.peer_id,"enabled":true,"credential_hash":&hash};
    let Some(peer)=app.collection("private_peers").find_one(filter).await? else {
        if let Some(observed)=observed{app.private_relay.withdraw_bound(&input.peer_id,&hash,&input.instance,observed);}
        return Err(forbidden("Private credential invalid or revoked"));
    };
    #[cfg(feature="private-sparse")]
    let _workspace_guard=crate::private_renumber::fence::stable(&app,peer.get_object_id("workspace_id").map_err(|_|forbidden("Invalid workspace"))?).await?;
    #[cfg(feature="private-sparse")]
    let peer=app.collection("private_peers").find_one(doc!{"_id":&input.peer_id,"workspace_id":peer.get("workspace_id"),"enabled":true,"credential_hash":&hash}).await?
        .ok_or_else(||forbidden("Private credential changed or was revoked while waiting"))?;
    if peer.contains_key("virtual_parent") && (!super::virtual_hosts::parent_valid(&app,&peer).await? || input.virtual_host_provider || input.native_repair.is_some() || input.exit_pick.is_some() || input.exit_pair_protocol.is_some() || input.exit_ready || input.lan_exit || input.tor_exit || input.application_proxy || !input.lan_networks.is_empty()){
        return Err(forbidden("Virtual provider unavailable or unsupported agent capability"));
    }
    #[cfg(feature="private-sparse")]
    let admission=app.private_relay.begin_workspace_admission(&input.peer_id,&hash,&input.instance,&peer.get_object_id("workspace_id").map_err(|_|forbidden("Invalid workspace"))?.to_hex())
        .ok_or_else(||ApiError::new(StatusCode::SERVICE_UNAVAILABLE,"Private control admission is busy; retry"))?;
    #[cfg(not(feature="private-sparse"))]
    let admission=app.private_relay.begin_admission(&input.peer_id,&hash,&input.instance)
        .ok_or_else(||ApiError::new(StatusCode::SERVICE_UNAVAILABLE,"Private control admission is busy; retry"))?;
    let observed_pairs=if cfg!(feature="private-sparse")&&input.sparse.is_some(){app.private_relay.observe_pairs(&input.peer_id,&hash,&input.instance,admission)}else{HashMap::new()};
    let observed_exit_pairs=if cfg!(feature="private-sparse")&&input.exit_pair_protocol==Some(1){app.private_relay.observe_exit_pairs(&input.peer_id,&hash,&input.instance,admission)}else{HashMap::new()};
    let cursor = if raw_watch { peer.get_object_id("workspace_id").ok().and_then(|owner|app.private_changes.subscribe(owner)).and_then(|ws| {
        let peer_cursor = app.private_changes.subscribe_peer(&input.peer_id)?;
        let combined = notification_cursor(*ws.borrow(), *peer_cursor.borrow());
        Some(combined.to_string())
    }) } else { None };
    let workspace=peer.get_object_id("workspace_id").map_err(|_|forbidden("Invalid workspace"))?;
    let before=if wants_continuity {crate::private_continuity::witness(&app,workspace).await} else {None};
    let mut result=sync_admitted(&app,&input,peer,&hash,admission,observed_pairs,observed_exit_pairs,traffic).await;
    if result.as_ref().is_err_and(|e|matches!(e.status,StatusCode::UNAUTHORIZED|StatusCode::FORBIDDEN)){
        app.private_relay.withdraw_bound(&input.peer_id,&hash,&input.instance,admission);
    }
    if let (Ok(reply), Some(cursor)) = (&mut result, cursor) {
        if app.private_relay.change_workspace(&input.peer_id,&hash,&input.instance).is_some() {
            if let Some(generation)=before {
                if crate::private_continuity::witness(&app,workspace).await==Some(generation) {
                    reply.headers_mut().insert("x-porthub-workspace-generation",generation.to_string().parse().expect("UUID header"));
                }
            }
            reply.headers_mut().insert("x-porthub-private-cursor", cursor.parse().expect("UUID header"));
        }
    }
    result
}
/// Existing exit plans require complete participant identities. Unrelated peers
/// must not inherit that representation's fleet limit merely by sharing a tenant.
async fn requires_complete_exit_snapshot(app:&App,owner:mongodb::bson::oid::ObjectId,peer:&Document)->ApiResult<bool> {
    let mut routes=app.collection("private_exit_nodes")
        .find(doc!{"workspace_id":owner,"enabled":{"$ne":false}})
        .projection(doc!{"routing_selectors":1,"distribution_selectors":1}).await?;
    let Some(first)=routes.try_next().await? else{return Ok(false)};
    let Some(machine_id)=peer.get("machine_id") else{return Ok(true)};
    let Some(machine)=crate::private_sparse::machine(app,owner,peer).await? else{return Ok(true)};
    let id=store::id(Some(machine_id));
    let participates=|route:&Document| ["routing_selectors","distribution_selectors"].iter()
        .any(|key|crate::routes::exit_nodes::matches_selectors(route,key,&id,&machine));
    if participates(&first){return Ok(true)}
    while let Some(route)=routes.try_next().await?{if participates(&route){return Ok(true)}}
    Ok(false)
}
async fn sync_admitted(app:&Arc<App>,input:&private_sync::Sync,peer:Document,hash:&str,admission:u64,mut observed_pairs:HashMap<String,crate::private_relay::PairPeerPin>,mut observed_exit_pairs:HashMap<String,crate::private_relay::PairPeerPin>,traffic:Option<Result<porthub_mesh::traffic_report::Report,serde_json::Error>>)->ApiResult<Response>{
    let filter=doc!{"_id":&input.peer_id,"enabled":true,"credential_hash":hash};
    let owner = peer
        .get_object_id("workspace_id")
        .map_err(|_| forbidden("Machine or workspace membership is disabled"))?;
    let indexed=if cfg!(feature="private-sparse") && input.sparse.is_some()
        && (peer.contains_key("virtual_parent")||input.exit_pair_protocol==Some(1)||!requires_complete_exit_snapshot(app,owner,&peer).await?) {
        Some(crate::private_sparse::select(&app,owner,&peer,input.sparse.as_ref().expect("negotiated request")).await?)
    }else{None};
    let (mut peers,mut inventory)=if let Some(indexed)=&indexed{(indexed.peers.clone(),indexed.inventory.clone())}else{active(&app,owner).await?};
    if !peers
        .iter()
        .any(|p| store::string(p, "_id") == input.peer_id)
    {
        return Err(forbidden("Machine or workspace membership is disabled"));
    }
    // Measurement failure must never deny an otherwise valid policy lease.
    let mut traffic_ack=None;
    let mut traffic_rejected=false;
    let mut traffic_discarded_rows=0;
    if let Some(report)=traffic {
        match report {
            Ok(report) if report.valid()=>{
                let ingest=async {
                    if indexed.is_some() { crate::private_traffic::ingest_sparse(&app,owner,&input.peer_id,&report).await }
                    else { crate::private_traffic::ingest(&app,owner,&input.peer_id,&peers,&report).await }
                };
                match tokio::time::timeout(Duration::from_millis(500),ingest).await {
                    Ok(Ok((ack,discarded)))=>{traffic_ack=Some(ack);traffic_discarded_rows=discarded;},
                    _=>traffic_rejected=true,
                }
            },
            _=>traffic_rejected=true,
        }
    }
    if input.paths.len() > 1000 {
        return Err(ApiError::bad_request("Too many path reports"));
    }
    indexes(&app).await?;
    let now = DateTime::now();
    let fields=doc!{"virtual_host_provider":input.virtual_host_provider,"fingerprint":&input.fingerprint,"instance":&input.instance,"stream_transport":&input.stream_transport,"tor_exit":input.tor_exit,"lan_networks":&input.lan_networks,"lan_exit":input.lan_exit,"application_proxy":input.application_proxy,"exit_pair_protocol":input.exit_pair_protocol,"exit_ready":input.exit_ready,"last_seen_at":now,
        "paths":mongodb::bson::to_document(&input.paths).expect("string map")};
    let mut pinned=filter.clone();
    let identity_fields=["instance","fingerprint","virtual_host_provider","lan_exit","tor_exit","application_proxy"];
    let changed=identity_fields.iter().any(|key|peer.get(*key)!=fields.get(*key));
    for field in identity_fields {
        pinned.insert(field,peer.get(field).cloned().unwrap_or(mongodb::bson::Bson::Null));
    }
    let heartbeat=async {
        app.collection("private_peers").find_one_and_update(pinned,doc!{"$set":fields,"$inc":{"revision":1_i64}})
            .return_document(ReturnDocument::After).await?
            .ok_or_else(||ApiError::new(StatusCode::CONFLICT,"Private identity changed during sync; retry"))
    };
    let updated=if changed {crate::private_continuity::write(app,Some(owner),heartbeat).await?}else{heartbeat.await?};
    #[cfg(feature="private-sparse")]
    if let Some(repair)=&input.native_repair{crate::private_renumber::native_repair::record(app,owner,&updated,repair).await?;}
    for p in &mut peers {
        if store::string(p, "_id") == input.peer_id {
            *p = updated.clone();
        }
    }
    let (prefs,suffix,names,machine_docs)=if let Some(indexed)=&indexed {
        (indexed.prefs.clone(),indexed.suffix.clone(),indexed.names.clone(),indexed.inventory.values().cloned().collect::<Vec<_>>())
    }else{
        let prefs = app
        .collection("private_networks")
        .find_one(doc! {"_id":owner.to_hex()})
        .await?
        .unwrap_or_default();
    let (_, suffix) = enrollment::preferences(&prefs)?;
    let all: Vec<Document> = app
        .collection("private_peers")
        .find(doc! {"workspace_id":owner})
        .projection(doc! {"machine_id":1,"created_at":1,"hostname":1})
        .await?
        .try_collect()
        .await?;
    let ids: Vec<_> = all
        .iter()
        .filter_map(|p| p.get("machine_id").cloned())
        .collect();
    let machine_docs: Vec<Document> = app
        .collection("machines")
        .find(doc! {"$or":[{"user_id":owner},{"_id":{"$in":ids}}],"deletion_pending":{"$ne":true}})
        .projection(doc! {"name":1,"aliases":1,"private_domains":1})
        .await?
        .try_collect()
        .await?;
    let names = private_names::assign(&machine_docs, &all);
        (prefs,suffix,names,machine_docs)
    };
    let mut dns_suffixes: HashSet<String> = [suffix.to_ascii_lowercase()].into_iter().collect();
    if let Some(indexed)=&indexed {dns_suffixes.extend(indexed.suffixes.iter().cloned());}
    let mut domains_by_machine = HashMap::new();
    for machine in &machine_docs {
        let domains = crate::domain::private_domains::from_document(machine);
        for domain in domains.iter().filter(|domain| !domain.default) {
            dns_suffixes.insert(domain.suffix.clone());
        }
        domains_by_machine.insert(store::id(machine.get("_id")), domains);
    }
    let wire_peer = |p: &Document| {
        let id=store::string(p,"_id");let machine_id=store::id(p.get("machine_id"));
        let mut aliases=names.aliases.get(id).into_iter().flatten().map(|name|format!("{name}.{suffix}")).collect::<Vec<_>>();
        aliases.extend(domains_by_machine.get(&machine_id).into_iter().flatten().filter(|domain| !domain.default).map(|domain|format!("{}.{}",domain.host,domain.suffix)));
        let online = p.get_datetime("last_seen_at").is_ok_and(|seen| {
            let age = now.timestamp_millis() - seen.timestamp_millis();
            (0..15_000).contains(&age)
        }) && !store::string(p, "fingerprint").is_empty() && !store::string(p, "instance").is_empty();
        json!({"id":id,"online":online,"ip":store::field(p,"ip"),"fingerprint":store::string(p,"fingerprint"),"instance":store::string(p,"instance"),"stream_transport":store::string(p,"stream_transport"),"lan_networks":p.get_array("lan_networks").cloned().unwrap_or_default(),
            "hostname":format!("{}.{suffix}",names.primary.get(id).map(String::as_str).unwrap_or("machine")),"aliases":aliases})
    };
    let sparse_rules=if indexed.is_some(){Some(crate::private_sparse::rules(&app,owner).await?)}else{None};
    let indexed_groups=if let Some(rules)=&sparse_rules{Some(crate::private_sparse::groups(&app,owner,&rules.index,&peers.iter().map(|p|store::id(p.get("owner_id"))).collect::<Vec<_>>()).await?)}else{None};
    let groups:Vec<Document>=if let Some(groups)=&indexed_groups{groups.values().map(|v|mongodb::bson::to_document(v).expect("typed group view")).collect()}else{
        app
        .collection("machine_groups")
        .find(doc! {"user_id":owner})
        .await?
        .try_collect()
        .await?
    };
    let exit_definitions: Vec<Document> = if peer.contains_key("virtual_parent"){Vec::new()}else{app.collection("private_exit_nodes")
        .find(doc! {"workspace_id":owner,"enabled":{"$ne":false}})
        .sort(doc! {"created_at":1,"_id":1})
        .await?.try_collect().await?};
    let exit_negotiated=input.exit_pair_protocol==Some(1)&&indexed.is_some();
    let own_exit_machine=inventory.get(&store::id(updated.get("machine_id"))).expect("active own machine");
    if cfg!(feature="private-sparse"){crate::private_exit_picker::publish(app,owner,&updated,own_exit_machine,&exit_definitions,exit_negotiated,input.exit_ready).await?;}
    let mut exit_intents=if exit_negotiated{crate::private_exit_picker::intents(&exit_definitions,&updated,own_exit_machine)?}else{Vec::new()};
    crate::private_exit_picker::capture_networks(app,owner,&mut exit_intents).await?;
    let relevant_exit_definitions:Vec<_>=exit_definitions.iter().filter(|r|exit_intents.iter().any(|i|i.id==store::id(r.get("_id")))).map(store::document).collect();
    let exit_epoch=exit_negotiated.then(||crate::domain::private_pairs::local_exit_epoch(&store::document(own_exit_machine),&store::document(&updated),&relevant_exit_definitions));
    let selection_epoch=exit_negotiated.then(||crate::domain::private_pairs::local_exit_selection_epoch(&store::document(own_exit_machine),&store::document(&updated),&relevant_exit_definitions));
    let picked=if let (Some(request),Some(exit_epoch))=(&input.exit_pick,&exit_epoch){
        if selection_epoch.as_deref()!=Some(request.selection_epoch.as_str()){Some(crate::private_exit_picker::Pick::Unavailable)}else{

        if let Some(route)=exit_definitions.iter().find(|r|store::id(r.get("_id"))==request.route_id){Some(crate::private_exit_picker::pick(app,owner,&updated,own_exit_machine,route,exit_epoch,request).await?)}else{Some(crate::private_exit_picker::Pick::Unavailable)}
        }
    }else{None};
    if let Some(crate::private_exit_picker::Pick::Peer(target))=&picked{
        if !peers.iter().any(|p|p.get("_id")==target.get("_id")){
            let machine=crate::private_sparse::machine(app,owner,target).await?.ok_or_else(||forbidden("Exit machine changed"))?;
            inventory.insert(store::id(target.get("machine_id")),machine);peers.push(target.clone());
        }
    }
    let exit_routes: Vec<Value> = exit_definitions.iter().filter(|_|!exit_negotiated).filter_map(|route| {
        let mut ranked_peers: Vec<_> = peers.iter().filter_map(|peer| {
            if route.get_str("traffic_mode").unwrap_or("internet_only") != "internet_only"
                && peer.get_bool("lan_exit") != Ok(true) { return None; }
            let machine_id = store::id(peer.get("machine_id"));
            let machine = inventory.get(&machine_id)?;
            let priority = crate::routes::exit_nodes::selector_priority(route, "routing_selectors", &machine_id, machine)?;
            Some((priority, machine_id, store::string(peer, "_id").to_owned()))
        }).collect();
        ranked_peers.sort();
        let mut routing_peers: Vec<_> = ranked_peers.into_iter().map(|(_, _, id)| id).collect();
        let mut clients: Vec<_> = peers.iter().filter(|p| {
            if route.get_str("traffic_mode").unwrap_or("internet_only") != "internet_only"
                && p.get_bool("lan_exit") != Ok(true) { return false; }
            if route.get_bool("tor_enabled") == Ok(true) && p.get_bool("tor_exit") != Ok(true) { return false; }
            let machine_id=store::id(p.get("machine_id"));
            inventory.get(&machine_id).is_some_and(|machine| crate::routes::exit_nodes::matches_selectors(route,"distribution_selectors",&machine_id,machine))
        }).map(|p|store::string(p,"_id").to_owned()).collect();
        let is_client = clients.contains(&input.peer_id);
        let is_exit = routing_peers.contains(&input.peer_id);
        if !is_client && !is_exit { return None; }
        // Disclose only the participating side of this route to each peer.
        // Transport reachability does not add ordinary private-port grants.
        if !is_exit { clients.retain(|id| id == &input.peer_id); }
        if !is_client { routing_peers.retain(|id| id == &input.peer_id); }
        ((!routing_peers.is_empty() || route.get_bool("tor_enabled")==Ok(true)) && !clients.is_empty()).then(|| json!({"id":store::id(route.get("_id")),"name":store::string(route,"name"),"routing_peers":routing_peers,"clients":clients,
            "selection":route.get_str("selection").unwrap_or("sticky"),"allow_direct_fallback":route.get_bool("allow_direct_fallback").unwrap_or(false),"tor_enabled":is_client && route.get_bool("tor_enabled").unwrap_or(false),"tor_circuit_groups":route.get_i64("tor_circuit_groups").unwrap_or(4),"traffic_mode":route.get_str("traffic_mode").unwrap_or("internet_only"),"masquerade":true,"block_lan_access":route.get_str("traffic_mode").unwrap_or("internet_only") == "internet_only"}))
    }).collect();
    let books:Vec<Document>=if sparse_rules.is_some(){Vec::new()}else{
        app
        .collection("access_rulebooks")
        .find(doc! {"user_id":owner})
        .await?
        .try_collect()
        .await?
    };
    let mut machines = Vec::new();
    let mut mapping = HashMap::new();
    for p in &peers {
        let mid = store::id(p.get("machine_id"));
        let mut machine = inventory[&mid].clone();
        machine.insert("user_id", owner);
        machine.insert(
            "private_owner_id",
            p.get("owner_id").cloned().unwrap_or_default(),
        );
        machines.push(store::document(&machine));
        mapping.insert(mid, store::id(p.get("_id")));
    }
    let groups: HashMap<_, _> = groups
        .iter()
        .map(|g| (store::id(g.get("_id")), store::document(g)))
        .collect();
    let books = books.iter().map(store::document).collect::<Vec<_>>();
    // Exit policies retain the complete legacy representation until their independently
    // bounded sparse exit-plan protocol is negotiated; never truncate an exit's client list.
    let sparse_request = input.sparse.as_ref().filter(|_| cfg!(feature="private-sparse") && indexed.is_some());
    let epoch=sparse_request.map(|_|{
        let own_machine=machines.iter().find(|m|m["_id"]==store::id(peer.get("machine_id"))).expect("active local machine");
        let manifest=sparse_rules.as_ref().map(|r|r.manifest.iter().map(store::document).collect::<Vec<_>>()).unwrap_or_else(||books.clone());
        crate::domain::private_pairs::local_epoch(own_machine,&manifest,&groups,&store::document(&peer))
    });
    let mut selected = Vec::new();
    if let Some(request) = sparse_request {
        for query in &request.wanted {
            let mut matches=peers.iter().filter(|p| {
                let value=wire_peer(p);
                match query.kind.as_str() {
                    "peer"=>store::string(p,"_id")==query.value,
                    "ip"=>store::string(p,"ip")==query.value,
                    "name"=>{
                        let name=query.value.trim_end_matches('.').to_ascii_lowercase();
                        value["hostname"].as_str().is_some_and(|v|v.eq_ignore_ascii_case(&name))
                            || value["aliases"].as_array().into_iter().flatten().any(|v|v.as_str().is_some_and(|v|v.eq_ignore_ascii_case(&name)))
                    }, _=>false,
                }
            });
            let first=matches.next();
            // Never choose one of multiple bindings or reveal an inaccessible name as allowed.
            selected.push((query.clone(),if matches.next().is_none(){first}else{None}));
        }
        if let Some(crate::private_exit_picker::Pick::Peer(target))=&picked{
            let id=store::string(target,"_id");
            if !selected.iter().any(|(_,p)|p.is_some_and(|p|store::string(p,"_id")==id)){
                selected.push((crate::domain::private_pairs::Lookup{kind:"peer".into(),value:id.into()},peers.iter().find(|p|store::string(p,"_id")==id)));
            }
        }
        // A cold receiver learns only recently authorized incident peers, not the whole workspace.
        for id in app.private_relay.pair_neighbors(&input.peer_id).into_iter().take(16) {
            if selected.len()>=32 {break;}
            if !selected.iter().any(|(_,p)|p.is_some_and(|p|store::string(p,"_id")==id)) {
                selected.push((crate::domain::private_pairs::Lookup{kind:"peer".into(),value:id.clone()},peers.iter().find(|p|store::string(p,"_id")==id)));
            }
        }
    }
    let own_machine_id=store::id(peer.get("machine_id"));
    let mut resolutions=Vec::new();let mut retirements=Vec::new();let mut exit_retirements=Vec::new();
    let mut retirement=|query:&crate::domain::private_pairs::Lookup,target:Option<&Document>|->Option<crate::private_relay::PairPeerPin>{
        let id=target.map(|p|store::string(p,"_id").to_owned()).or_else(||match query.kind.as_str(){
            "peer"=>Some(query.value.clone()),
            "ip"=>{let ip=query.value.parse::<std::net::Ipv4Addr>().ok()?;let mut found=observed_pairs.values().filter(|p|p.ip==ip);let first=found.next()?.id.clone();found.next().is_none().then_some(first)},
            _=>None,
        })?;observed_pairs.remove(&id)
    };
    let mut sparse_reachable=HashSet::new();
    let mut exit_pairs=HashMap::new();
    let mut grants = if sparse_request.is_some() {
        for (query,target) in selected {
            let pair=target.map(|p|{
                if let Some(rules)=&sparse_rules{
                    let source=machines.iter().find(|m|m["_id"]==own_machine_id).expect("local machine");
                    let target=machines.iter().find(|m|m["_id"]==store::id(p.get("machine_id"))).expect("selected machine");
                    rules.index.pair(source,target,&groups)
                }else{private_policy::compile_pair(&machines,&books,&groups,&own_machine_id,&store::id(p.get("machine_id")))}
            }).unwrap_or_default();
            let exit=if let (Some(target),Some(exit_epoch))=(target,&exit_epoch){
                if target.get_i32("exit_pair_protocol").ok().or_else(||target.get_i64("exit_pair_protocol").ok().map(|v|v as i32))==Some(1){
                    crate::private_exit_picker::pair(&exit_definitions,&updated,&inventory[&own_machine_id],target,&inventory[&store::id(target.get("machine_id"))],exit_epoch)?
                }else{None}
            }else{None};
            if exit.is_none(){
                let id=target.map(|p|store::string(p,"_id").to_owned()).or_else(||match query.kind.as_str(){
                    "peer"=>Some(query.value.clone()),
                    "ip"=>query.value.parse::<std::net::Ipv4Addr>().ok().and_then(|ip|{let mut matches=observed_exit_pairs.values().filter(|p|p.ip==ip);let first=matches.next()?.id.clone();matches.next().is_none().then_some(first)}),
                    _=>None,
                });
                if let Some(id)=id{if let Some(pin)=observed_exit_pairs.remove(&id){exit_retirements.push(pin);}}
            }
            if pair.is_empty()&&exit.is_none(){if let Some(pin)=retirement(&query,target){retirements.push(pin);}resolutions.push((query,None,None));continue;}
            if let Some(exit)=exit{exit_pairs.insert(store::string(target.expect("exit counterpart"),"_id").to_owned(),exit);}

            let id=store::string(target.expect("nonempty exact pair"),"_id");
            let acl=porthub_network::policy::pair_acl::PairAcl::from_iter(&input.peer_id,id,pair.into_iter().map(|g|porthub_network::policy::Grant{
                source:mapping[&g.source].clone(),destination:mapping[&g.destination].clone(),protocol:g.protocol,
                ports:g.ports.into_iter().map(|p|porthub_network::policy::Port{start:p.start,end:p.end}).collect(),
            })).ok();
            if acl.is_some()||exit_pairs.contains_key(id){sparse_reachable.insert(id.to_owned());}else if let Some(pin)=retirement(&query,target){retirements.push(pin);}
            resolutions.push((query,target,acl));
        }
        Vec::new()
    } else {private_policy::compile_for(&machines,&books,&groups,&own_machine_id)};
    let mut reachable = HashSet::from([input.peer_id.clone()]);
    reachable.extend(sparse_reachable);
    for grant in &mut grants {
        grant.source = mapping[&grant.source].clone();
        grant.destination = mapping[&grant.destination].clone();
        reachable.insert(grant.source.clone());
        reachable.insert(grant.destination.clone());
    }
    let exit_neighbors: HashSet<String> = exit_routes.iter().flat_map(|route| {
        ["routing_peers", "clients"].into_iter().flat_map(|key| {
            route[key].as_array().into_iter().flatten().filter_map(Value::as_str)
        }).filter(|id| *id != input.peer_id).map(str::to_owned)
    }).collect();
    reachable.extend(exit_neighbors.iter().cloned());
    let by_id: HashMap<_, _> = peers
        .iter()
        .filter(|p| reachable.contains(store::string(p, "_id")))
        .map(|p| (store::string(p, "_id"), p))
        .collect();
    for signal in &input.signals {
        let Some(target) = by_id
            .get(signal.to.as_str())
            .filter(|p| signal.to != input.peer_id && !store::string(p, "fingerprint").is_empty())
        else {
            continue;
        };
        validate_signal(&input.peer_id, &signal.to, signal, &input.fingerprint)?;
        // Bind both process instances and certificates, including the target,
        // so an old session cannot be replayed after a restart or key change.
        let key = json!([
            input.peer_id,
            input.instance,
            input.fingerprint,
            signal.to,
            store::string(target, "instance"),
            store::string(target, "fingerprint"),
            signal.session,
            signal.description.r#type,
            if signal.description.r#type == "candidate" {
                &signal.description.sdp
            } else {
                ""
            }
        ])
        .to_string();
        app.collection("private_signals").update_one(doc!{"_id":token_digest(&key)},doc!{"$setOnInsert":{
            "from":&input.peer_id,"to":&signal.to,"source_instance":&input.instance,"target_instance":store::string(target,"instance"),
            "session":&signal.session,"fingerprint":&input.fingerprint,"target_fingerprint":store::string(target,"fingerprint"),
            "description":mongodb::bson::to_document(&signal.description).expect("typed description"),
            "expires_at":DateTime::from_millis(now.timestamp_millis()+45_000)}}).upsert(true).await?;
    }
    if !input.acks.is_empty() {
        app.collection("private_signals")
            .delete_many(doc! {"_id":{"$in":&input.acks},"to":&input.peer_id})
            .await?;
    }
    let reachable: Vec<_> = reachable.into_iter().collect();
    let incoming:Vec<Document>=app.collection("private_signals").find(doc!{"to":&input.peer_id,"target_instance":&input.instance,"target_fingerprint":&input.fingerprint,
        "from":{"$in":reachable},"expires_at":{"$gt":now}}).limit(128).await?.try_collect().await?;
    let signals:Vec<_>=incoming.iter().filter(|s|by_id.get(store::string(s,"from")).is_some_and(|p|
        s.get("source_instance")==p.get("instance") && s.get("fingerprint")==p.get("fingerprint")))
        .map(|s|json!({"id":store::field(s,"_id"),"from":store::field(s,"from"),"session":store::field(s,"session"),"description":store::field(s,"description")})).collect();
    let wire_peers:Vec<_>=peers.iter().filter(|p|by_id.contains_key(store::string(p,"_id"))).map(wire_peer).collect();
    let current = app
        .collection("private_peers")
        .find_one(filter)
        .await?
        .ok_or_else(|| forbidden("Private credential revoked"))?;
    if store::string(&current, "instance") != input.instance
        || store::string(&current, "fingerprint") != input.fingerprint
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "Private client instance changed; retry sync",
        ));
    }
    let own_machine = app.collection("machines").find_one(doc!{"_id":current.get("machine_id"),"user_id":current.get("owner_id"),
        "enabled":{"$ne":false},"deletion_pending":{"$ne":true},"private_owner_revoked":{"$ne":true}}).projection(doc!{"_id":1}).await?;
    let own_owner = store::id(current.get("owner_id"));
    let still_member=own_owner==owner.to_hex() || app.collection("workspace_members").find_one(doc!{"workspace_id":owner,"user_id":current.get("owner_id"),"role":{"$in":["admin","member"]}}).projection(doc!{"_id":1}).await?.is_some();
    if own_machine.is_none() || !still_member {
        return Err(forbidden("Machine or workspace membership is disabled"));
    }
    let fallback: Vec<_> = app
        .config
        .tunnel_fallback_base_urls
        .iter()
        .map(|s| {
            let s = s.trim_end_matches('/');
            s.strip_suffix("/api").unwrap_or(s).to_owned()
        })
        .collect();
    if indexed.is_some() && !exit_negotiated && requires_complete_exit_snapshot(app,owner,&peer).await? {
        return Err(ApiError::new(StatusCode::CONFLICT,"Private exit assignment changed; retry sync"));
    }
    if let Some(rules)=&sparse_rules{crate::private_sparse::verify_rules(&app,owner,rules).await?;}
    if let Some(indexed)=&indexed{if app.collection("private_name_directory_state").find_one(doc!{"_id":owner.to_hex(),"generation":&indexed.generation,"ready":true}).projection(doc!{"_id":1}).await?.is_none(){return Err(ApiError::bad_request("Private directory changed; retry discovery"));}}
    // Explicit complete legacy failure, never a truncated authorization snapshot.
    if epoch.is_none() && (wire_peers.len()>4096 || grants.len()>65536) {
        return Err(ApiError::bad_request("Private policy exceeds this client's identity capacity; upgrade to negotiated sparse private networking or narrow the rule"));
    }
    // A picker directory/cursor is never a grant. Revalidate the semantic
    // source generation and each exact counterpart immediately before Hub
    // publication, including membership/credentials changed during the scan.
    let mut target_exit_epochs=HashMap::new();
    if let Some(source_exit_epoch)=&exit_epoch {
        let latest_routes:Vec<Document>=app.collection("private_exit_nodes").find(doc!{"workspace_id":owner,"enabled":{"$ne":false}}).sort(doc!{"created_at":1,"_id":1}).await?.try_collect().await?;
        let latest_machine=crate::private_sparse::machine(app,owner,&current).await?.ok_or_else(||forbidden("Exit source ownership changed"))?;
        let latest_intents=crate::private_exit_picker::intents(&latest_routes,&current,&latest_machine)?;
        let latest_relevant:Vec<_>=latest_routes.iter().filter(|r|latest_intents.iter().any(|i|i.id==store::id(r.get("_id")))).map(store::document).collect();
        if crate::domain::private_pairs::local_exit_epoch(&store::document(&latest_machine),&store::document(&current),&latest_relevant)!=*source_exit_epoch{
            return Err(ApiError::new(StatusCode::CONFLICT,"Private exit source assignment changed; retry selection"));
        }
        if selection_epoch.as_deref()!=Some(crate::domain::private_pairs::local_exit_selection_epoch(&store::document(&latest_machine),&store::document(&current),&latest_relevant).as_str()){
            return Err(ApiError::new(StatusCode::CONFLICT,"Private exit selection changed during lookup; retry sync"));
        }
        let ids:Vec<_>=exit_pairs.keys().cloned().collect();
        let (fresh,inventory)=active_matching(app,owner,Some(&ids)).await?;
        for (id,issued) in &exit_pairs {
            let target=fresh.iter().find(|p|store::string(p,"_id")==id).ok_or_else(||forbidden("Exit target ownership changed"))?;
            let observed=peers.iter().find(|p|store::string(p,"_id")==id).expect("selected exit peer");
            for field in ["credential_hash","instance","fingerprint","ip","exit_pair_protocol"]{
                if target.get(field)!=observed.get(field){return Err(ApiError::new(StatusCode::CONFLICT,"Private exit target generation changed; retry selection"));}
            }
            let machine=&inventory[&store::id(target.get("machine_id"))];
            let latest=crate::private_exit_picker::pair(&latest_routes,&current,&latest_machine,target,machine,source_exit_epoch)?;
            if serde_json::to_value(latest).expect("typed exit")!=serde_json::to_value(Some(issued)).expect("typed exit"){
                return Err(ApiError::new(StatusCode::CONFLICT,"Private exit target assignment changed; retry selection"));
            }
            let intents=crate::private_exit_picker::intents(&latest_routes,target,machine)?;
            let relevant:Vec<_>=latest_routes.iter().filter(|r|intents.iter().any(|i|i.id==store::id(r.get("_id")))).map(store::document).collect();
            target_exit_epochs.insert(id.clone(),crate::domain::private_pairs::local_exit_epoch(&store::document(machine),&store::document(target),&relevant));
        }
    }
    let mut relay_auth_token = String::new();
    if let Ok(ip) = store::string(&current, "ip").parse() {
        let mut allowed: HashSet<String> = grants
            .iter()
            .filter_map(|grant| {
                if grant.source == input.peer_id {
                    Some(grant.destination.clone())
                } else if grant.destination == input.peer_id {
                    Some(grant.source.clone())
                } else {
                    None
                }
            })
            .collect();
        allowed.extend(exit_neighbors.iter().cloned());
        relay_auth_token = if let Some(epoch)=&epoch {
            if let Some(exit_epoch)=&exit_epoch{app.private_relay.publish_sparse_exit_admitted(&input.peer_id,hash,&input.instance,ip,epoch,exit_epoch,Some(admission))}
            else{app.private_relay.publish_sparse_admitted(&input.peer_id,hash,&input.instance,ip,epoch,Some(admission))}
        } else {app.private_relay.publish_admitted(&input.peer_id,hash,&input.instance,ip,allowed,Some(admission))};
    }
    if relay_auth_token.is_empty(){return Err(ApiError::new(StatusCode::CONFLICT,"Private authority changed or is busy; retry sync"));}
    let source_origin:porthub_network::policy::PeerInfo=serde_json::from_value(wire_peer(&updated)).map_err(|_|ApiError::bad_request("Invalid relay origin identity"))?;
    if !app.private_relay.bind_origin(source_origin,hash,admission){return Err(ApiError::new(StatusCode::CONFLICT,"Private relay identity changed; retry sync"));}

    for target in retirements{app.private_relay.retire_pair_admitted(&input.peer_id,hash,&input.instance,admission,&target);}
    for target in exit_retirements{app.private_relay.retire_exit_pair_admitted(&input.peer_id,hash,&input.instance,admission,&target);}

    let mut pair_responses=Vec::new();let mut pair_response_bytes=0usize;
    if let Some(epoch)=&epoch {
        let local:porthub_network::policy::PeerInfo=serde_json::from_value(wire_peer(&updated)).map_err(|_|ApiError::bad_request("Invalid local sparse identity"))?;
        for (query,target,acl) in resolutions {
            let Some(target)=target else {push_pair_response(&mut pair_responses,&mut pair_response_bytes,json!({"query":query,"status":"unavailable"}));continue;};
            if acl.is_none()&&!exit_pairs.contains_key(store::string(target,"_id")){push_pair_response(&mut pair_responses,&mut pair_response_bytes,json!({"query":query,"status":"policy_capacity"}));continue;}
            let id=store::string(target,"_id");
            let revision=target.get_i64("revision").ok().filter(|v|*v>0).unwrap_or(0) as u64;
            let target_machine=machines.iter().find(|m|m["_id"]==store::id(target.get("machine_id"))).expect("selected target");
            let manifest=sparse_rules.as_ref().map(|r|r.manifest.iter().map(store::document).collect::<Vec<_>>()).unwrap_or_else(||books.clone());
            let target_epoch=crate::domain::private_pairs::local_epoch(target_machine,&manifest,&groups,&store::document(target));
            if revision==0 {
                push_pair_response(&mut pair_responses,&mut pair_response_bytes,json!({"query":query,"status":"busy"}));continue;
            }
            let mut remote:porthub_network::policy::PeerInfo=serde_json::from_value(wire_peer(target)).map_err(|_|ApiError::bad_request("Invalid remote sparse identity"))?;
            app.private_relay.project_origin(&mut remote,store::string(target,"credential_hash"));
            let lease=porthub_network::policy::PairLease{workspace:owner.to_hex(),self_:input.peer_id.clone(),epoch:epoch.clone(),expires_at:chrono::DateTime::from_timestamp_millis(now.timestamp_millis()+15_000).expect("current timestamp"),revision,local:local.clone(),peer:remote,grants:vec![],acl,exit:exit_pairs.get(id).cloned()};
            let value=json!({"query":query,"status":"allowed","lease":lease});
            if pair_response_bytes.saturating_add(serde_json::to_vec(&value).expect("typed lease").len())>PAIR_REPLY_BYTES-16384{
                push_pair_response(&mut pair_responses,&mut pair_response_bytes,json!({"query":query,"status":"busy"}));continue;
            }
            let pin=crate::private_relay::PairPeerPin{id:id.into(),hash:store::string(target,"credential_hash").into(),instance:store::string(target,"instance").into(),ip:store::string(target,"ip").parse().map_err(|_|ApiError::bad_request("Invalid private peer IP"))?,epoch:Some(target_epoch.clone()),origin_stamp:lease.peer.relay_origin.clone(),generation:None};
            let private_binding = if lease.acl.is_some() {
                app.private_relay.publish_pair_update(&input.peer_id,epoch,hash,&input.instance,admission,&pin)
            } else { Some(false) };
            let private_ok = private_binding.is_some();
            let exit_ok=if let Some(exit)=&lease.exit{
                let mut pin=pin;pin.epoch=target_exit_epochs.get(id).cloned();
                app.private_relay.publish_exit_pair_admitted(&input.peer_id,&exit.epoch,hash,&input.instance,admission,&pin)
            }else{true};
            if !private_ok||!exit_ok {
                // Backpressure never renews the independently expiring Hub pair authority.
                push_pair_response(&mut pair_responses,&mut pair_response_bytes,json!({"query":query,"status":"busy"}));continue;
            }
            if private_binding == Some(true) { app.private_changes.peer_ready(id); }
            push_pair_response(&mut pair_responses,&mut pair_response_bytes,value);
        }
    }
    let capture_pools=if epoch.is_some(){crate::domain::private_networks::pools(&prefs)?.iter().map(|p|p.cidr()).collect::<Vec<_>>()}else{Vec::new()};
    if capture_pools.len()>porthub_network::capture_routes::MAX_CAPTURE_PREFIXES {
        return Err(ApiError::bad_request("Private capture route capacity exceeded; operator review required"));
    }
    // This origin is configured by the gateway operator and returned only to
    // authenticated private clients. HTTP origins are supported by operator
    // choice; their bearer headers and raw fallback packets are not encrypted.
    // Sparse packet fallback uses the secure profile endpoint when the configured
    // direct origin has no TLS. Legacy negotiation retains its operator override.
    let direct_relay_url = app
        .config
        .gateway_advertised_url
        .as_deref()
        .filter(|url| url.starts_with("https://") || (epoch.is_none() && url.starts_with("http://")))
        .map(|url| url.trim_end_matches('/').to_owned());
    let dns_document = app.collection("private_dns_rules").find_one(doc! {"workspace_id":owner,"machine_id":current.get("machine_id")}).await?;
    let dns_rules = dns_document.as_ref().map(|value|crate::routes::dns_rules::blocking_rules(store::field(value,"rules"))).unwrap_or_else(||json!([]));
    let proxy_provider = if input.application_proxy {
        if let Ok(machine)=current.get_object_id("machine_id") {app.proxy_pending.is_provider(&app,owner,machine).await} else {false}
    } else {false};
    app.proxy_pending.publish(crate::peer_proxy::Binding {id:input.peer_id.clone(),instance:input.instance.clone(),fingerprint:input.fingerprint.clone()},&hash,owner.to_hex(),proxy_provider);
    let proxy_jobs=app.proxy_pending.jobs(&input.peer_id,&input.instance,&input.fingerprint);
    let mut response=json!({"traffic_ack":traffic_ack,"traffic_rejected":traffic_rejected,"traffic_discarded_rows":traffic_discarded_rows,"snapshot":{"workspace":owner.to_hex(),"self":input.peer_id,"revision":store::field(&updated,"revision"),"dns_rules":dns_rules,
        "expires_at":chrono::DateTime::from_timestamp_millis(now.timestamp_millis()+15_000).expect("current timestamp").to_rfc3339_opts(chrono::SecondsFormat::Millis,true),"peers":if epoch.is_some(){wire_peers.iter().filter(|p|p["id"]==input.peer_id).cloned().collect::<Vec<_>>()}else{wire_peers},"sparse":epoch.as_ref().map(|epoch|json!({"protocol":1,"epoch":epoch,"capture_pools":capture_pools})),"dns_suffixes":dns_suffixes,"grants":if epoch.is_some(){Vec::<private_policy::Grant>::new()}else{grants},"exit_routes":exit_routes},"signals":signals,
        "ice_servers":app.config.private_transport.ice(&input.peer_id,now.timestamp_millis()/1000),"relay_routes":app.config.private_transport.relay_routes,
        "direct_relay_url":direct_relay_url,"relay_auth_token":relay_auth_token,"proxy_jobs":proxy_jobs,"proxy_provider":proxy_provider,
        "sparse_sequence":sparse_request.map(|r|r.sequence),"pair_responses":pair_responses,"control_fallback_urls":fallback,"poll_seconds":1});
    if input.virtual_host_provider { response["virtual_hosts"]=json!(super::virtual_hosts::assignments(app,&updated,&input.token).await?); }
    if exit_negotiated{
        response["snapshot"]["sparse"]["exit_epoch"]=json!(exit_epoch);
        response["snapshot"]["sparse"]["selection_epoch"]=json!(selection_epoch);
        response["snapshot"]["sparse"]["exit_intents"]=json!(exit_intents);
    }
    if let (Some(request),Some(picked),Some(exit_epoch))=(&input.exit_pick,picked,exit_epoch){
        use porthub_network::policy::{ExitPickResponse,ExitPickStatus,ExitChoice};
        use crate::private_exit_picker::Pick;
        let (status,choice,lease,cursor)=match picked{
            Pick::Pending(cursor)=>(ExitPickStatus::Pending,None,None,Some(cursor)),
            Pick::Peer(target)=>{
                let id=store::string(&target,"_id");
                let lease=response["pair_responses"].as_array().into_iter().flatten().find(|r|r["status"]=="allowed"&&r["lease"]["peer"]["id"]==id).and_then(|r|serde_json::from_value(r["lease"].clone()).ok());
                if let Some(lease)=lease{(ExitPickStatus::Ready,Some(ExitChoice::Peer{id:id.into()}),Some(lease),None)}else{(ExitPickStatus::Unavailable,None,None,None)}
            },
            Pick::LocalTor=>(ExitPickStatus::Ready,Some(ExitChoice::LocalTor),None,None),
            Pick::Unavailable=>(ExitPickStatus::Unavailable,None,None,None),
            Pick::UpgradeRequired=>(ExitPickStatus::UpgradeRequired,None,None,None),
        };
        let reply=ExitPickResponse{route_id:request.route_id.clone(),flow_id:request.flow_id.clone(),ordinal:request.ordinal,warmup:request.warmup,discover:request.discover,selection_epoch:request.selection_epoch.clone(),epoch:exit_epoch.clone(),status,choice,lease,cursor};
        reply.validate_for(request,&exit_epoch).map_err(|_|ApiError::bad_request("Invalid exit picker publication"))?;
        response["exit_pick"]=serde_json::to_value(reply).expect("typed picker response");
    }
    // The finite-stream sender waits for a delivery receipt for each 8 KiB.
    // On WAN links this stalls native TCP until its original admission expires.
    // Let sparse clients use the authorized packet transport for new flows.
    if cfg!(feature = "private-sparse") && epoch.is_some() {
        response["stream_protocols"] = json!([]);
    }
    if epoch.is_none() {
        response["snapshot"].as_object_mut().expect("snapshot object").remove("sparse");
        let root=response.as_object_mut().expect("sync object");root.remove("sparse_sequence");root.remove("pair_responses");
    }
    if let Some(nonce) = &input.clock_nonce {
        if input.refresh_clock_origin {
            response["clock_origin"] = crate::gateway_origin::clock_origin(&app).unwrap_or(serde_json::Value::Null);
        }
        response["authority_clock"] = json!({"nonce": nonce, "server_time": chrono::Utc::now()});
    }
    if serde_json::to_vec(&response).expect("typed control response").len()>4*1024*1024 {
        return Err(ApiError::new(StatusCode::SERVICE_UNAVAILABLE,"Private control reply exceeds bounded capacity; retry a smaller discovery batch"));
    }
    if input.pinned_relay && epoch.is_some() {
        if let Some(origin) = crate::gateway_origin::pinned_private_relay(&app) {
            response["pinned_relay"] = origin;
        }
    }
    Ok(([(header::CACHE_CONTROL,"no-store")],Json(response)).into_response())
}

#[cfg(test)]
mod sparse_response_budget_tests{
    use super::*;
    #[test]
    fn overload_returns_exact_query_busy_without_partial_lease_or_unrelated_eviction(){
        let mut out=Vec::new();let mut bytes=0;
        let query=json!({"kind":"peer","value":"requested"});
        push_pair_response(&mut out,&mut bytes,json!({"query":query,"status":"allowed","lease":{"bounded_test_payload":"x".repeat(PAIR_REPLY_BYTES)}}));
        assert_eq!(out[0],json!({"query":query,"status":"busy"}));assert!(bytes<256);
        let other=json!({"query":{"kind":"peer","value":"other"},"status":"unavailable"});
        push_pair_response(&mut out,&mut bytes,other.clone());assert_eq!(out[1],other);assert!(bytes<PAIR_REPLY_BYTES);
    }
}

#[cfg(all(test,feature="private-sparse"))]
mod renumber_wait_tests {
    use super::*;
    use anyhow::{ensure,Result};
    #[tokio::test]
    #[ignore="requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
    async fn sync_waiting_on_migration_rereads_address_revocation_and_rotated_credential()->Result<()> {
        let client=mongodb::Client::with_uri_str(std::env::var("PORTHUB_TEST_MONGO_URI")?).await?;
        let db=client.database(&format!("porthub_renumber_wait_{}",uuid::Uuid::new_v4().simple()));
        let app=Arc::new(App::new(crate::config::Config::default(),db.clone()));
        let result=async {
            for kind in ["address","revoked","rotated"] {
                let owner=ObjectId::new();let mid=ObjectId::new();let id=format!("{owner}:{mid}");
                let token="fixture-token-0123456789abcdef0123456789";
                app.collection("users").insert_one(doc!{"_id":owner,"enabled":true}).await?;
                app.collection("machines").insert_one(doc!{"_id":mid,"user_id":owner,"name":"Migration fixture"}).await?;
                app.collection("private_peers").insert_one(doc!{"_id":&id,"workspace_id":owner,"owner_id":owner,"machine_id":mid,"enabled":true,"credential_hash":token_digest(token),"ip":"10.203.0.2"}).await?;
                let guard=crate::private_renumber::fence::stable(&app,owner).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
                let request=json!({"peer_id":id,"token":token,"fingerprint":vec!["AB";32].join(":"),"instance":"instance-00000000","sparse":{"protocol":1,"sequence":1,"wanted":[]}});
                let task={let app=app.clone();tokio::spawn(async move{sync(State(app),ApiBody(request)).await})};
                let waited=tokio::time::timeout(Duration::from_secs(3),async {
                    loop {if app.private_sparse.workspace_fences.waiting(&owner.to_hex()).await {break;} tokio::task::yield_now().await;}
                }).await;
                if waited.is_err(){task.abort();drop(guard);let _=task.await;anyhow::bail!("sync did not reach the held workspace fence");}
                let update=match kind {"address"=>doc!{"$set":{"ip":"10.204.0.2"}},"revoked"=>doc!{"$set":{"enabled":false}},_=>doc!{"$set":{"credential_hash":token_digest("replacement-credential")}}};
                app.collection("private_peers").update_one(doc!{"_id":&id},update).await?;
                if kind=="address" {app.collection("private_renumber_heads").insert_one(doc!{"_id":owner.to_hex(),"generation":1_i64,"state":"stable"}).await?;}
                drop(guard);
                let actual=tokio::time::timeout(Duration::from_secs(5),task).await??;
                if kind=="address" {
                    let response=actual.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
                    let body=axum::body::to_bytes(response.into_body(),4*1024*1024).await?;
                    let body:Value=serde_json::from_slice(&body)?;
                    ensure!(body["snapshot"]["peers"].as_array().is_some_and(|rows|rows.iter().any(|p|p["id"]==id&&p["ip"]=="10.204.0.2")),"stale pre-fence address leaked: {body}");
                }else {ensure!(actual.err().is_some_and(|e|e.status==StatusCode::FORBIDDEN),"revoked/rotated waiter published authority");}
            }
            Ok::<_,anyhow::Error>(())
        }.await;
        db.drop().await?;result
    }
}
