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
    let retired = crate::account_delete::retiring_owners(app).await?;
    if retired.contains(&mongodb::bson::Bson::ObjectId(owner)) {
        return Ok((Vec::new(), HashMap::new()));
    }
    let peers: Vec<Document> = app
        .collection("private_peers")
        .find(doc! {"workspace_id":owner,"owner_id":{"$nin":retired},"enabled":true})
        .await?
        .try_collect()
        .await?;
    let ids: Vec<_> = peers
        .iter()
        .filter_map(|p| p.get("machine_id").cloned())
        .collect();
    let machines:Vec<Document>=app.collection("machines").find(doc!{"_id":{"$in":ids},"enabled":{"$ne":false},"deletion_pending":{"$ne":true},"private_owner_revoked":{"$ne":true}})
        .projection(doc!{"user_id":1,"private_owner_id":1,"private_owner_revoked":1,"enabled":1,"group_ids":1,"group_id":1}).await?.try_collect().await?;
    let members: Vec<Document> = app
        .collection("workspace_members")
        .find(doc! {"workspace_id":owner,"role":{"$in":["member","admin"]}})
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
    let peers = peers
        .into_iter()
        .filter(|p| {
            valid.contains(&store::id(p.get("owner_id")))
                && inventory
                    .get(&store::id(p.get("machine_id")))
                    .is_some_and(|m| m.get("user_id") == p.get("owner_id"))
        })
        .collect();
    Ok((peers, inventory))
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

async fn sync(State(app): State<Arc<App>>, ApiBody(raw): ApiBody) -> ApiResult<Response> {
    let input=private_sync::parse(raw)?;let hash=token_digest(&input.token);
    let filter=doc!{"_id":&input.peer_id,"enabled":true,"credential_hash":&hash};
    let Some(peer)=app.collection("private_peers").find_one(filter).await? else {
        app.private_relay.withdraw_bound(&input.peer_id,&hash,&input.instance,None);
        return Err(forbidden("Private credential invalid or revoked"));
    };
    let admission=app.private_relay.begin_admission(&input.peer_id,&hash,&input.instance)
        .ok_or_else(||ApiError::new(StatusCode::SERVICE_UNAVAILABLE,"Private control admission is busy; retry"))?;
    let result=sync_admitted(&app,&input,peer,&hash,admission).await;
    if result.as_ref().is_err_and(|e|matches!(e.status,StatusCode::UNAUTHORIZED|StatusCode::FORBIDDEN)){
        app.private_relay.withdraw_bound(&input.peer_id,&hash,&input.instance,Some(admission));
    }
    result
}
async fn sync_admitted(app:&Arc<App>,input:&private_sync::Sync,peer:Document,hash:&str,admission:u64)->ApiResult<Response>{
    let filter=doc!{"_id":&input.peer_id,"enabled":true,"credential_hash":hash};
    let owner = peer
        .get_object_id("workspace_id")
        .map_err(|_| forbidden("Machine or workspace membership is disabled"))?;
    let indexed=if cfg!(feature="private-sparse") && input.sparse.is_some()
        && app.collection("private_exit_nodes").find_one(doc!{"workspace_id":owner,"enabled":{"$ne":false}}).projection(doc!{"_id":1}).await?.is_none() {
        Some(crate::private_sparse::select(&app,owner,&peer,input.sparse.as_ref().expect("negotiated request")).await?)
    }else{None};
    let (mut peers,inventory)=if let Some(indexed)=&indexed{(indexed.peers.clone(),indexed.inventory.clone())}else{active(&app,owner).await?};
    if !peers
        .iter()
        .any(|p| store::string(p, "_id") == input.peer_id)
    {
        return Err(forbidden("Machine or workspace membership is disabled"));
    }
    if input.paths.len() > 1000 {
        return Err(ApiError::bad_request("Too many path reports"));
    }
    indexes(&app).await?;
    let now = DateTime::now();
    let updated=app.collection("private_peers").find_one_and_update(filter.clone(),doc!{"$set":{"fingerprint":&input.fingerprint,"instance":&input.instance,"stream_transport":&input.stream_transport,"tor_exit":input.tor_exit,"lan_networks":&input.lan_networks,"lan_exit":input.lan_exit,"application_proxy":input.application_proxy,"last_seen_at":now,
        "paths":mongodb::bson::to_document(&input.paths).expect("string map")},"$inc":{"revision":1_i64}}).return_document(ReturnDocument::After).await?
        .ok_or_else(||forbidden("Private credential revoked"))?;
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
    let exit_definitions: Vec<Document> = app.collection("private_exit_nodes")
        .find(doc! {"workspace_id":owner,"enabled":{"$ne":false}})
        .sort(doc! {"created_at":1,"_id":1})
        .await?.try_collect().await?;
    let exit_routes: Vec<Value> = exit_definitions.iter().filter_map(|route| {
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
        // A cold receiver learns only recently authorized incident peers, not the whole workspace.
        for id in app.private_relay.pair_neighbors(&input.peer_id).into_iter().take(16) {
            if selected.len()>=32 {break;}
            if !selected.iter().any(|(_,p)|p.is_some_and(|p|store::string(p,"_id")==id)) {
                selected.push((crate::domain::private_pairs::Lookup{kind:"peer".into(),value:id.clone()},peers.iter().find(|p|store::string(p,"_id")==id)));
            }
        }
    }
    let own_machine_id=store::id(peer.get("machine_id"));
    let mut resolutions=Vec::new();
    let mut grants = if sparse_request.is_some() {
        let mut result=Vec::new();
        for (query,target) in selected {
            let pair=target.map(|p|{
                if let Some(rules)=&sparse_rules{
                    let source=machines.iter().find(|m|m["_id"]==own_machine_id).expect("local machine");
                    let target=machines.iter().find(|m|m["_id"]==store::id(p.get("machine_id"))).expect("selected machine");
                    rules.index.pair(source,target,&groups)
                }else{private_policy::compile_pair(&machines,&books,&groups,&own_machine_id,&store::id(p.get("machine_id")))}
            }).unwrap_or_default();
            if pair.is_empty(){if let Some(peer)=target{app.private_relay.revoke_pair(&input.peer_id,store::string(peer,"_id"));}resolutions.push((query,None,Vec::new()));continue;}
            if pair.len()>128 {resolutions.push((query,None,Vec::new()));continue;}
            result.extend(pair.iter().cloned());resolutions.push((query,target,pair));
        }
        result
    } else {private_policy::compile_for(&machines,&books,&groups,&own_machine_id)};
    let mut reachable = HashSet::from([input.peer_id.clone()]);
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
    if let Some(rules)=&sparse_rules{crate::private_sparse::verify_rules(&app,owner,rules).await?;}
    if let Some(indexed)=&indexed{if app.collection("private_name_directory_state").find_one(doc!{"_id":owner.to_hex(),"generation":&indexed.generation,"ready":true}).projection(doc!{"_id":1}).await?.is_none(){return Err(ApiError::bad_request("Private directory changed; retry discovery"));}}
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
            app.private_relay.publish_sparse_admitted(&input.peer_id,hash,&input.instance,ip,epoch,Some(admission))
        } else {app.private_relay.publish_admitted(&input.peer_id,hash,&input.instance,ip,allowed,Some(admission))};
    }
    if relay_auth_token.is_empty(){return Err(ApiError::new(StatusCode::CONFLICT,"Private authority changed or is busy; retry sync"));}
    let mut pair_responses=Vec::new();
    if let Some(epoch)=&epoch {
        let local:porthub_network::policy::PeerInfo=serde_json::from_value(wire_peer(&updated)).map_err(|_|ApiError::bad_request("Invalid local sparse identity"))?;
        for (query,target,pair) in resolutions {
            let Some(target)=target else {pair_responses.push(json!({"query":query,"status":"unavailable"}));continue;};
            let id=store::string(target,"_id");
            let revision=target.get_i64("revision").ok().filter(|v|*v>0).unwrap_or(0) as u64;
            let target_machine=machines.iter().find(|m|m["_id"]==store::id(target.get("machine_id"))).expect("selected target");
            let manifest=sparse_rules.as_ref().map(|r|r.manifest.iter().map(store::document).collect::<Vec<_>>()).unwrap_or_else(||books.clone());
            let target_epoch=crate::domain::private_pairs::local_epoch(target_machine,&manifest,&groups,&store::document(target));
            if revision==0 || !app.private_relay.publish_pair_epochs(&input.peer_id,id,epoch,&target_epoch) {
                pair_responses.push(json!({"query":query,"status":"busy"}));continue;
            }
            let remote:porthub_network::policy::PeerInfo=serde_json::from_value(wire_peer(target)).map_err(|_|ApiError::bad_request("Invalid remote sparse identity"))?;
            let grants=pair.into_iter().map(|mut g|{g.source=mapping[&g.source].clone();g.destination=mapping[&g.destination].clone();g}).collect::<Vec<_>>();
            let grants=serde_json::from_value(serde_json::to_value(grants).expect("typed grants")).expect("compatible packet grants");
            let lease=porthub_network::policy::PairLease{workspace:owner.to_hex(),self_:input.peer_id.clone(),epoch:epoch.clone(),expires_at:chrono::DateTime::from_timestamp_millis(now.timestamp_millis()+15_000).expect("current timestamp"),revision,local:local.clone(),peer:remote,grants};
            pair_responses.push(json!({"query":query,"status":"allowed","lease":lease}));
        }
    }
    let capture_pools=if epoch.is_some(){crate::domain::private_networks::pools(&prefs)?.iter().map(|p|p.cidr()).collect::<Vec<_>>()}else{Vec::new()};
    if capture_pools.len()>porthub_network::capture_routes::MAX_CAPTURE_PREFIXES {
        return Err(ApiError::bad_request("Private capture route capacity exceeded; operator review required"));
    }
    // Explicit complete legacy failure, never a truncated authorization snapshot.
    if epoch.is_none() && (wire_peers.len()>4096 || grants.len()>65536) {
        return Err(ApiError::bad_request("Private policy exceeds this client's identity capacity; upgrade to negotiated sparse private networking or narrow the rule"));
    }
    // This origin is configured by the gateway operator and returned only to
    // authenticated private clients. HTTP origins are supported by operator
    // choice; their bearer headers and raw fallback packets are not encrypted.
    // Stream payloads retain their independent peer encryption.
    let direct_relay_url = app
        .config
        .gateway_advertised_url
        .as_deref()
        .filter(|url| url.starts_with("http://") || url.starts_with("https://"))
        .map(|url| url.trim_end_matches('/').to_owned());
    let dns_document = app.collection("private_dns_rules").find_one(doc! {"workspace_id":owner,"machine_id":current.get("machine_id")}).await?;
    let dns_rules = dns_document.as_ref().map(|value|crate::routes::dns_rules::blocking_rules(store::field(value,"rules"))).unwrap_or_else(||json!([]));
    let proxy_provider = if input.application_proxy {
        if let Ok(machine)=current.get_object_id("machine_id") {app.proxy_pending.is_provider(&app,owner,machine).await} else {false}
    } else {false};
    app.proxy_pending.publish(crate::peer_proxy::Binding {id:input.peer_id.clone(),instance:input.instance.clone(),fingerprint:input.fingerprint.clone()},&hash,owner.to_hex(),proxy_provider);
    let proxy_jobs=app.proxy_pending.jobs(&input.peer_id,&input.instance,&input.fingerprint);
    let mut response=json!({"snapshot":{"workspace":owner.to_hex(),"self":input.peer_id,"revision":store::field(&updated,"revision"),"dns_rules":dns_rules,
        "expires_at":chrono::DateTime::from_timestamp_millis(now.timestamp_millis()+15_000).expect("current timestamp").to_rfc3339_opts(chrono::SecondsFormat::Millis,true),"peers":if epoch.is_some(){wire_peers.iter().filter(|p|p["id"]==input.peer_id).cloned().collect::<Vec<_>>()}else{wire_peers},"sparse":epoch.as_ref().map(|epoch|json!({"protocol":1,"epoch":epoch,"capture_pools":capture_pools})),"dns_suffixes":dns_suffixes,"grants":if epoch.is_some(){Vec::<private_policy::Grant>::new()}else{grants},"exit_routes":exit_routes},"signals":signals,
        "ice_servers":app.config.private_transport.ice(&input.peer_id,now.timestamp_millis()/1000),"relay_routes":app.config.private_transport.relay_routes,
        "direct_relay_url":direct_relay_url,"relay_auth_token":relay_auth_token,"proxy_jobs":proxy_jobs,"proxy_provider":proxy_provider,
        "sparse_sequence":sparse_request.map(|r|r.sequence),"pair_responses":pair_responses,"control_fallback_urls":fallback,"poll_seconds":1});
    if epoch.is_none() {
        response["snapshot"].as_object_mut().expect("snapshot object").remove("sparse");
        let root=response.as_object_mut().expect("sync object");root.remove("sparse_sequence");root.remove("pair_responses");
    }
    Ok(([(header::CACHE_CONTROL,"no-store")],Json(response)).into_response())
}
