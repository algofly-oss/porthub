//! Bounded server-side exit selection. Directory rows and cursors are hints;
//! every examined candidate is freshly authorized before it participates.
use crate::{
    error::{ApiError, ApiResult},
    store, App,
};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, DateTime, Document};
use porthub_network::policy::ExitPickRequest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::Ipv4Addr;
const PAGE: usize = 256;
const CURSOR_TTL: i64 = 120_000;
#[derive(Clone, Serialize, Deserialize, Default)]
struct Progress {
    after: String,
    count: u64,
    best: Option<String>,
    score: String,
    prefix: Option<u8>,
    priority: Option<i64>,
    select_rank: Option<u64>,
    rank: u64,
    upgrade: bool,
}
pub enum Pick {
    Pending(String),
    Peer(Document),
    LocalTor,
    Unavailable,
    UpgradeRequired,
}
fn fail() -> ApiError {
    ApiError::bad_request("Exit selection changed or cursor expired; retry cold flow")
}
fn stamp(request: &ExitPickRequest, epoch: &str, source: &Document) -> String {
    let mut request = request.clone();
    request.cursor = None;
    format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&(
                request,
                epoch,
                store::string(source, "credential_hash"),
                store::string(source, "instance"),
                store::string(source, "fingerprint")
            ))
            .expect("typed picker scope")
        )
    )
}
fn online(peer: &Document, now: i64) -> bool {
    peer.get_datetime("last_seen_at")
        .is_ok_and(|v| (0..15_000).contains(&(now - v.timestamp_millis())))
        && !store::string(peer, "fingerprint").is_empty()
        && !store::string(peer, "instance").is_empty()
}
fn accepts(route: &Document, peer: &Document, machine: &Document, role: &str) -> bool {
    let mode = route.get_str("traffic_mode").unwrap_or("internet_only");
    (mode == "internet_only" || peer.get_bool("lan_exit") == Ok(true))
        && (role != "distribution_selectors"
            || route.get_bool("tor_enabled") != Ok(true)
            || peer.get_bool("tor_exit") == Ok(true))
        && crate::routes::exit_nodes::matches_selectors(
            route,
            role,
            &store::id(peer.get("machine_id")),
            machine,
        )
}
/// Publish only this authenticated node's current router roles. This collection
/// is a bounded-row index per configured router, never an authorization source.
pub async fn publish(
    app: &App,
    owner: ObjectId,
    peer: &Document,
    machine: &Document,
    routes: &[Document],
    protocol: bool,
    ready: bool,
) -> ApiResult<()> {
    app.private_sparse
        .exit_indexes
        .get_or_try_init(|| async {
            use mongodb::{options::IndexOptions, IndexModel};
            app.collection("private_exit_routers")
                .create_index(
                    IndexModel::builder()
                        .keys(doc! {"workspace_id":1,"route_id":1,"peer":1})
                        .options(IndexOptions::builder().unique(true).build())
                        .build(),
                )
                .await?;
            for name in ["private_exit_routers", "private_exit_picker_cursors"] {
                app.collection(name)
                    .create_index(
                        IndexModel::builder()
                            .keys(doc! {"expires_at":1})
                            .options(
                                IndexOptions::builder()
                                    .expire_after(std::time::Duration::ZERO)
                                    .build(),
                            )
                            .build(),
                    )
                    .await?;
            }
            Ok::<_, ApiError>(())
        })
        .await?;
    let id = store::string(peer, "_id");
    let mut keep = Vec::new();
    for route in routes
        .iter()
        .filter(|r| accepts(r, peer, machine, "routing_selectors"))
    {
        let route_id = store::id(route.get("_id"));
        keep.push(route_id.clone());
        let key = format!("{}:{}:{}", owner, route_id, id);
        app.collection("private_exit_routers").update_one(doc!{"_id":key},doc!{"$set":{"workspace_id":owner,"route_id":route_id,"peer":id,"protocol":protocol,"ready":ready,"lan_networks":peer.get_array("lan_networks").cloned().unwrap_or_default(),"expires_at":DateTime::from_millis(DateTime::now().timestamp_millis()+15_000)}}).upsert(true).await?;
    }
    app.collection("private_exit_routers")
        .delete_many(doc! {"workspace_id":owner,"peer":id,"route_id":{"$nin":keep}})
        .await?;
    Ok(())
}
fn lan_prefix(peer: &Document, destination: Ipv4Addr) -> Option<u8> {
    peer.get_array("lan_networks")
        .ok()?
        .iter()
        .filter_map(|v| {
            v.as_str()?
                .parse::<porthub_mesh::lan_routes::Network>()
                .ok()
        })
        .filter(|net| net.contains(destination))
        .map(|net| net.prefix())
        .max()
}
fn rendezvous(client: &str, id: &str) -> String {
    let mut hash = Sha256::new();
    hash.update((client.len() as u64).to_be_bytes());
    hash.update(client);
    hash.update(id);
    format!("{:x}", hash.finalize())
}
/// Each RPC holds at most PAGE candidates, folds at most4096, and yields at
/// the next batch boundary after250ms. A single protected cursor slot
/// per source prevents an unbounded in-memory cold-flow cache on the API.
pub async fn pick(
    app: &App,
    owner: ObjectId,
    source: &Document,
    machine: &Document,
    route: &Document,
    epoch: &str,
    request: &ExitPickRequest,
) -> ApiResult<Pick> {
    request.validate().map_err(|_| fail())?;
    if store::id(route.get("_id")) != request.route_id
        || !accepts(route, source, machine, "distribution_selectors")
    {
        return Ok(Pick::Unavailable);
    }
    let source_id = store::string(source, "_id");
    let key = format!("{owner}:{source_id}");
    let binding = stamp(request, epoch, source);
    let now = DateTime::now();
    let mut state = if let Some(cursor) = &request.cursor {
        let row = app
            .collection("private_exit_picker_cursors")
            .find_one(doc! {"_id":&key,"token":cursor,"binding":&binding,"expires_at":{"$gt":now}})
            .await?
            .ok_or_else(fail)?;
        mongodb::bson::from_document::<Progress>(
            row.get_document("progress").map_err(|_| fail())?.clone(),
        )
        .map_err(|_| fail())?
    } else {
        Progress::default()
    };
    let started = std::time::Instant::now();
    let mut work = 0usize;
    loop {
        let rows:Vec<Document>=app.collection("private_exit_routers").find(doc!{"workspace_id":owner,"route_id":&request.route_id,"peer":{"$gt":&state.after},"expires_at":{"$gt":now}})
        .sort(doc!{"peer":1}).limit((PAGE+1) as i64).await?.try_collect().await?;
        let more = rows.len() > PAGE;
        let page = &rows[..rows.len().min(PAGE)];
        work += page.len();
        let ids: Vec<String> = page
            .iter()
            .map(|r| store::string(r, "peer").to_owned())
            .collect();
        let (active, inventory) =
            crate::routes::private_sync::active_matching(app, owner, Some(&ids)).await?;
        for row in page {
            let id = store::string(row, "peer");
            state.after = id.into();
            if id == source_id {
                continue;
            }
            let Some(peer) = active.iter().find(|p| store::string(p, "_id") == id) else {
                continue;
            };
            if !online(peer, now.timestamp_millis()) {
                continue;
            }
            let Some(target) = inventory.get(&store::id(peer.get("machine_id"))) else {
                continue;
            };
            if !accepts(route, peer, &target, "routing_selectors") {
                continue;
            }
            if row.get_bool("protocol") != Ok(true) {
                state.upgrade = true;
                continue;
            }
            if row.get_bool("ready") != Ok(true) {
                continue;
            }
            if request.unavailable_peers.iter().any(|failed|failed==id){continue}
            if !request.warmup && !request.discover
                && request
                    .available_peers
                    .as_ref()
                    .is_some_and(|v| !v.iter().any(|v| v == id))
            {
                continue;
            }
            if let Some(wanted) = state.select_rank {
                if state.rank == wanted {
                    state.best = Some(id.into());
                }
                state.rank += 1;
                continue;
            }
            state.count += 1;
            if request.destination.is_private() && !request.warmup {
                let prefix = lan_prefix(peer, request.destination);
                let priority = crate::routes::exit_nodes::selector_priority(
                    route,
                    "routing_selectors",
                    &store::id(peer.get("machine_id")),
                    &target,
                )
                .map(|v| v as i64)
                .unwrap_or(i64::MAX);
                let better = prefix.is_some()
                    && (state.prefix.is_none()
                        || prefix > state.prefix
                        || (prefix == state.prefix
                            && (state.priority.is_none_or(|p| priority < p)
                                || (state.priority == Some(priority)
                                    && state.best.as_deref().is_none_or(|old| id < old)))));
                if better || state.count == 1 {
                    state.best = Some(id.into());
                    state.prefix = prefix;
                    state.priority = Some(priority);
                }
            } else if request.warmup || route.get_str("selection").unwrap_or("sticky") == "sticky" {
                let score = rendezvous(source_id, id);
                if state.best.is_none() || score > state.score {
                    state.best = Some(id.into());
                    state.score = score;
                }
            }
        }
        let mut second_phase = false;
        let tor = !request.warmup && !request.destination.is_private()
            && route.get_bool("tor_enabled") == Ok(true)
            && request.local_tor_ready;
        if !more
            && state.select_rank.is_none()
            && (!request.destination.is_private() || request.warmup)
        {
            let mode = if request.warmup {
                "sticky"
            } else {
                route.get_str("selection").unwrap_or("sticky")
            };
            if tor {
                state.count += 1;
                if mode == "sticky" {
                    let score = rendezvous(source_id, "@local-tor");
                    if state.best.is_none() || score > state.score {
                        state.best = Some("local-tor".into());
                        state.score = score;
                    }
                }
            }
            if state.count > 0 && mode != "sticky" {
                let ordinal = if mode == "round_robin" {
                    request.ordinal
                } else {
                    let bytes = Sha256::digest(format!(
                        "{}:{}:{}",
                        request.flow_id, request.ordinal, owner
                    ));
                    u64::from_be_bytes(bytes[..8].try_into().expect("digest prefix"))
                };
                let rank = ordinal % state.count;
                if tor && rank == state.count - 1 {
                    return Ok(Pick::LocalTor);
                }
                state.select_rank = Some(rank);
                second_phase = true;
                state.after.clear();
                state.rank = 0;
            }
        }
        if more || second_phase {
            if work < 4096 && started.elapsed() < std::time::Duration::from_millis(250) {
                continue;
            }
            let token = uuid::Uuid::new_v4().simple().to_string();
            app.collection("private_exit_picker_cursors").replace_one(doc!{"_id":&key},doc!{"_id":key,"token":&token,"binding":binding,"expires_at":DateTime::from_millis(now.timestamp_millis()+CURSOR_TTL),"progress":mongodb::bson::to_document(&state).expect("typed cursor")}).upsert(true).await?;
            return Ok(Pick::Pending(token));
        }
        break;
    }
    app.collection("private_exit_picker_cursors")
        .delete_one(doc! {"_id":key})
        .await?;
    if request.destination.is_private()
        && !request.warmup
        && state.prefix.is_none()
        && state.count != 1
    {
        return Ok(Pick::Unavailable);
    }
    let Some(id) = state.best else {
        return Ok(if state.upgrade {
            Pick::UpgradeRequired
        } else {
            Pick::Unavailable
        });
    };
    if id == "local-tor" {
        return Ok(Pick::LocalTor);
    }
    // Reauthorize the winner after the complete scan; directory membership is
    // never enough to grant a pair or revive a revoked/deleted machine.
    let peer = crate::routes::private_sync::active_report_peers(app, owner, &[id.clone()])
        .await?
        .into_iter()
        .next();
    let Some(peer) = peer.filter(|p| online(p, DateTime::now().timestamp_millis())) else {
        return Err(fail());
    };
    let Some(target) = crate::private_sparse::machine(app, owner, &peer).await? else {
        return Err(fail());
    };
    if !accepts(route, &peer, &target, "routing_selectors") {
        return Err(fail());
    }
    Ok(Pick::Peer(peer))
}

/// Exact counterpart authority for either a client lookup or the router's
/// reciprocal incoming-EXIT lookup. Ordinary private ACLs are independent.
pub fn pair(
    routes: &[Document],
    local: &Document,
    local_machine: &Document,
    remote: &Document,
    remote_machine: &Document,
    epoch: &str,
) -> ApiResult<Option<porthub_network::policy::ExitPair>> {
    let mut found = None;
    for route in routes {
        let direction = if accepts(route, local, local_machine, "distribution_selectors")
            && accepts(route, remote, remote_machine, "routing_selectors")
        {
            Some((local, remote))
        } else if accepts(route, remote, remote_machine, "distribution_selectors")
            && accepts(route, local, local_machine, "routing_selectors")
        {
            Some((remote, local))
        } else {
            None
        };
        let Some((client, router)) = direction else {
            continue;
        };
        if found.is_some() {
            return Err(ApiError::bad_request(
                "Ambiguous recursive private exit assignment",
            ));
        }
        found = Some(porthub_network::policy::ExitPair {
            epoch: epoch.into(),
            route_id: store::id(route.get("_id")),
            client: store::string(client, "_id").into(),
            router: store::string(router, "_id").into(),
            traffic_mode: serde_json::from_value(serde_json::json!(route
                .get_str("traffic_mode")
                .unwrap_or("internet_only")))
            .map_err(|_| fail())?,
        });
    }
    Ok(found)
}
/// These are plumbing intents, not remote packet permissions.
pub fn intents(
    routes: &[Document],
    peer: &Document,
    machine: &Document,
) -> ApiResult<Vec<porthub_network::policy::ExitIntent>> {
    let mut out = Vec::new();
    for route in routes {
        let client = accepts(route, peer, machine, "distribution_selectors");
        let router = accepts(route, peer, machine, "routing_selectors");
        if client && router {
            return Err(ApiError::bad_request("Recursive private exit assignment"));
        }
        if !client && !router {
            continue;
        }
        let intent = porthub_network::policy::ExitIntent {
            id: store::id(route.get("_id")),
            name: store::string(route, "name").into(),
            role: if client {
                porthub_network::policy::ExitRole::Client
            } else {
                porthub_network::policy::ExitRole::Router
            },
            selection: serde_json::from_value(serde_json::json!(route
                .get_str("selection")
                .unwrap_or("sticky")))
            .map_err(|_| fail())?,
            traffic_mode: serde_json::from_value(serde_json::json!(route
                .get_str("traffic_mode")
                .unwrap_or("internet_only")))
            .map_err(|_| fail())?,
            allow_direct_fallback: route.get_bool("allow_direct_fallback").unwrap_or(false),
            tor_enabled: client && route.get_bool("tor_enabled").unwrap_or(false),
            tor_circuit_groups: route
                .get_i64("tor_circuit_groups")
                .unwrap_or(4)
                .try_into()
                .map_err(|_| fail())?,
            lan_networks: Vec::new(),
            masquerade: true,
            block_lan_access: route.get_str("traffic_mode").unwrap_or("internet_only")
                == "internet_only",
        };
        out.push(intent);
    }
    if out.len() > 256
        || out
            .iter()
            .filter(|v| v.role == porthub_network::policy::ExitRole::Client)
            .count()
            > 1
        || (out
            .iter()
            .any(|v| v.role == porthub_network::policy::ExitRole::Client)
            && out
                .iter()
                .any(|v| v.role == porthub_network::policy::ExitRole::Router))
    {
        return Err(ApiError::bad_request("Ambiguous private exit intent"));
    }
    Ok(out)
}

/// Exact union only: containment and sibling merges never capture an address
/// outside an advertisement. The host's existing native conflict guard remains
/// authoritative before any route is installed.
fn exact_union(
    mut input: Vec<porthub_mesh::lan_routes::Network>,
) -> Vec<porthub_mesh::lan_routes::Network> {
    use porthub_mesh::lan_routes::Network;
    input.sort_by_key(|n| (u32::from(n.address()), n.prefix()));
    let mut out: Vec<Network> = Vec::new();
    for network in input {
        if out.last().is_some_and(|parent| {
            parent.contains(network.address()) && parent.prefix() <= network.prefix()
        }) {
            continue;
        }
        out.push(network);
        loop {
            if out.len() < 2 {
                break;
            }
            let right = out[out.len() - 1];
            let left = out[out.len() - 2];
            if left.prefix() != right.prefix() || left.prefix() <= 1 {
                break;
            }
            let Ok(parent) = Network::from_address(left.address(), left.prefix() - 1) else {
                break;
            };
            if !parent.contains(right.address()) {
                break;
            }
            out.pop();
            out.pop();
            out.push(parent);
        }
    }
    out
}
pub async fn capture_networks(
    app: &App,
    owner: ObjectId,
    intents: &mut [porthub_network::policy::ExitIntent],
) -> ApiResult<()> {
    use porthub_mesh::{exit_policy::TrafficMode, lan_routes::Network};
    for intent in intents.iter_mut().filter(|i| {
        i.role == porthub_network::policy::ExitRole::Client
            && i.traffic_mode != TrafficMode::InternetOnly
    }) {
        let mut rows=app.collection("private_exit_routers").find(doc!{"workspace_id":owner,"route_id":&intent.id,"expires_at":{"$gt":DateTime::now()}}).projection(doc!{"lan_networks":1}).batch_size(128).await?;
        let mut networks = Vec::new();
        let mut peers = 0;
        while let Some(row) = rows.try_next().await? {
            peers += 1;
            for value in row.get_array("lan_networks").into_iter().flatten() {
                if let Some(raw) = value.as_str() {
                    networks.push(raw.parse::<Network>().map_err(|_| fail())?)
                }
            }
            // Exact incremental compaction; no truncation/false encompassing prefix.
            if networks.len() >= 4096 {
                networks = exact_union(networks);
            }
        }
        intent.lan_networks = if peers == 1 {
            ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
                .into_iter()
                .map(|s| s.parse().expect("RFC1918"))
                .collect()
        } else {
            exact_union(networks)
        };
        if intent.lan_networks.len() > porthub_network::capture_routes::MAX_CAPTURE_PREFIXES {
            return Err(ApiError::bad_request("Exit LAN capture plan exceeds exact native prefix capacity; no partial plan was published"));
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_capture_union_merges_siblings_but_never_fills_a_missing_subnet() {
        let parse = |values: &[&str]| values.iter().map(|s| s.parse().unwrap()).collect();
        let union = exact_union(parse(&[
            "10.1.0.0/24",
            "10.1.1.0/24",
            "10.1.0.0/25",
            "10.1.4.0/24",
        ]));
        assert_eq!(
            union.iter().map(ToString::to_string).collect::<Vec<_>>(),
            vec!["10.1.0.0/23", "10.1.4.0/24"]
        );
        assert!(!union
            .iter()
            .any(|n| n.contains("10.1.2.1".parse().unwrap())));
    }
}
