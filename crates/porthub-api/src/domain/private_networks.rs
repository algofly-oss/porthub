//! Gateway-wide private range allocation. Existing tenant addresses are never
//! renumbered automatically. Mutations are serialized by the single core API.
use super::enrollment::{self, Network};
use crate::{
    error::{ApiError, ApiResult},
    store, App,
};
use axum::http::StatusCode;
use futures_util::TryStreamExt;
use mongodb::bson::{doc, Document};
use std::{collections::HashSet, net::Ipv4Addr};

/// Additional pools share the same identity-based mesh and ACLs. Agents route
/// individual peer addresses, so growth never requires renumbering live peers.
pub fn pools(document: &Document) -> ApiResult<Vec<Network>> {
    let mut result = vec![enrollment::preferences(document)?.0];
    if let Some(value) = document.get("additional_cidrs") {
        let items = value
            .as_array()
            .ok_or_else(|| ApiError::bad_request("Invalid private address pools"))?;
        for value in items {
            let network = Network::parse(
                value
                    .as_str()
                    .ok_or_else(|| ApiError::bad_request("Invalid private address pool"))?,
            )
            .map_err(ApiError::bad_request)?;
            if !result.iter().any(|old| old.cidr() == network.cidr()) {
                result.push(network);
            }
        }
    }
    Ok(result)
}

pub fn describe(document: &Document) -> ApiResult<serde_json::Value> {
    let (primary, suffix) = enrollment::preferences(document)?;
    let ranges = pools(document)?;
    let capacity: u64 = ranges
        .iter()
        .filter(|range| {
            !ranges
                .iter()
                .any(|other| other.capacity() > range.capacity() && other.overlaps(**range))
        })
        .map(|range| u64::from(range.capacity()))
        .sum();
    Ok(
        serde_json::json!({"cidr":primary.cidr(),"dns_suffix":suffix,"auto_expand":true,
        "cidrs":ranges.iter().map(|range| range.cidr()).collect::<Vec<_>>(),"address_capacity":capacity}),
    )
}

fn overflow_candidates() -> impl Iterator<Item = Network> {
    (0..65536u32)
        .map(|offset| {
            let index = (203 * 256 + offset) % 65536;
            format!("10.{}.{}.0/24", index / 256, index % 256)
        })
        .chain((0..4096u32).map(|i| format!("172.{}.{}.0/24", 16 + i / 256, i % 256)))
        .chain((0..256u32).map(|i| format!("192.168.{i}.0/24")))
        .map(|cidr| Network::parse(&cidr).expect("RFC1918 candidate"))
}

async fn workspace_lans(
    app: &App,
    owner: &str,
) -> ApiResult<Vec<porthub_mesh::lan_routes::Network>> {
    let owner = mongodb::bson::oid::ObjectId::parse_str(owner)
        .map_err(|_| ApiError::bad_request("Invalid workspace"))?;
    let peers: Vec<Document> = app
        .collection("private_peers")
        .find(doc! {"workspace_id":owner,"enabled":{"$ne":false}})
        .projection(doc! {"lan_networks":1})
        .await?
        .try_collect()
        .await?;
    let mut lans = HashSet::new();
    for peer in peers {
        if let Ok(values) = peer.get_array("lan_networks") {
            for value in values {
                if let Some(raw) = value.as_str() {
                    if let Ok(network) = raw.parse::<porthub_mesh::lan_routes::Network>() {
                        lans.insert(network.to_string());
                    }
                }
            }
        }
    }
    Ok(lans
        .into_iter()
        .filter_map(|value| value.parse().ok())
        .collect())
}

fn avoids_lans(network: Network, lans: &[porthub_mesh::lan_routes::Network]) -> bool {
    let candidate: porthub_mesh::lan_routes::Network =
        network.cidr().parse().expect("validated private pool");
    !lans.iter().any(|lan| candidate.overlaps(*lan))
}

/// Caller holds private_network_lock through allocation AND peer insertion.
pub(crate) async fn allocate_locked(
    app: &App,
    owner: &str,
    machine: &str,
    used: &HashSet<String>,
) -> ApiResult<String> {
    let document = ensure_locked(app, owner).await?;
    let current = pools(&document)?;
    let lans = workspace_lans(app, owner).await?;
    for pool in &current {
        if !avoids_lans(*pool, &lans) {
            continue;
        }
        if let Some(ip) = pool.available_address(machine, used) {
            return Ok(ip);
        }
    }
    let (foreign, addresses) = occupied(app, owner).await?;
    // Prefer a contiguous expansion, but never claim another tenant's range.
    if let Some(parent) = current[0]
        .parent()
        .filter(|p| available(*p, &foreign, &addresses) && avoids_lans(*p, &lans))
    {
        if let Some(ip) = parent.available_address(machine, used) {
            app.collection("private_networks").update_one(doc! {"_id":owner},
                doc! {"$set":{"cidr":parent.cidr(),"updated_at":mongodb::bson::DateTime::now()}}).await?;
            return Ok(ip);
        }
    }
    let mut reserved = foreign;
    reserved.extend(current);
    let next = overflow_candidates()
        .find(|candidate| {
            available(*candidate, &reserved, &addresses) && avoids_lans(*candidate, &lans)
        })
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::CONFLICT,
                "All available RFC1918 private address pools are occupied",
            )
        })?;
    let ip = next.available_address(machine, used).ok_or_else(|| {
        ApiError::new(
            StatusCode::CONFLICT,
            "Private address pool allocation changed; retry",
        )
    })?;
    app.collection("private_networks").update_one(doc! {"_id":owner},
        doc! {"$addToSet":{"additional_cidrs":next.cidr()},"$set":{"updated_at":mongodb::bson::DateTime::now()}}).await?;
    Ok(ip)
}

async fn occupied(app: &App, owner: &str) -> ApiResult<(Vec<Network>, Vec<Ipv4Addr>)> {
    let networks: Vec<Document> = app
        .collection("private_networks")
        .find(doc! {"_id":{"$ne":owner}})
        .await?
        .try_collect()
        .await?;
    let mut ranges = Vec::new();
    let mut configured = std::collections::HashSet::new();
    for network in networks {
        configured.insert(store::string(&network, "_id").to_owned());
        ranges.extend(pools(&network)?);
    }
    #[cfg(feature="private-sparse")]
    {
        // Pending reservations survive a process crash and participate in ALL
        // other tenants' allocations before any partial assignment can exist.
        let mut pending=app.collection("private_renumber_heads").find(doc!{"_id":{"$ne":owner},"state":{"$ne":"stable"}}).projection(doc!{"target_cidrs":1}).await?;
        while let Some(head)=pending.try_next().await? {
            let pools=head.get_array("target_cidrs").map_err(|_|ApiError::bad_request("Invalid pending private migration reservation; recovery required"))?;
            if pools.is_empty()||pools.len()>32{return Err(ApiError::bad_request("Invalid pending migration reservation bounds"));}
            for raw in pools {ranges.push(Network::parse(raw.as_str().ok_or_else(||ApiError::bad_request("Invalid pending migration pool"))?).map_err(ApiError::bad_request)?);}
        }
    }
    // Reserve legacy defaults even when no preferences document was saved.
    // Also reserve old assigned addresses after a tenant edits its range.
    let mut addresses = Vec::new();
    let mut peers = app
        .collection("private_peers")
        .find(doc! {})
        .projection(doc! {"workspace_id":1,"ip":1})
        .await?;
    while let Some(peer) = peers.try_next().await? {
        let tenant = store::id(peer.get("workspace_id"));
        if tenant == owner {
            continue;
        }
        if configured.insert(tenant) {
            ranges.push(Network::parse("10.203.0.0/24").expect("default range"));
        }
        if let Ok(ip) = store::string(&peer, "ip").parse() {
            addresses.push(ip);
        }
    }
    {let(retired_ranges,retired_addresses)=crate::private_retired_sources::occupied(app).await?;ranges.extend(retired_ranges);addresses.extend(retired_addresses);}
    Ok((ranges, addresses))
}

fn available(candidate: Network, ranges: &[Network], addresses: &[Ipv4Addr]) -> bool {
    !ranges.iter().any(|range| candidate.overlaps(*range))
        && !addresses.iter().any(|ip| candidate.contains(*ip))
}

pub async fn ensure(app: &App, owner: &str) -> ApiResult<Document> {
    let _guard = app.private_network_lock.lock().await;
    #[cfg(feature="private-sparse")]
    let _workspace_guard=crate::private_renumber::fence::stable_with_allocation(app,mongodb::bson::oid::ObjectId::parse_str(owner).map_err(|_|ApiError::bad_request("Invalid workspace"))?).await?;
    ensure_locked(app, owner).await
}

// Caller holds private_network_lock through address allocation and insertion.
pub(crate) async fn ensure_locked(app: &App, owner: &str) -> ApiResult<Document> {
    if let Some(existing) = app
        .collection("private_networks")
        .find_one(doc! {"_id":owner})
        .await?
    {
        return Ok(existing);
    }
    let oid = mongodb::bson::oid::ObjectId::parse_str(owner)
        .map_err(|_| ApiError::bad_request("Invalid workspace"))?;
    let legacy = app
        .collection("private_peers")
        .find_one(doc! {"workspace_id":oid})
        .await?
        .is_some();
    let (ranges, addresses) = occupied(app, owner).await?;
    let mut chosen = None;
    // Prefer the historic default, then walk RFC1918 space in /24s.
    // Legacy tenants retain their default even if historical ranges overlap.
    for range in overflow_candidates() {
        if legacy || available(range, &ranges, &addresses) {
            chosen = Some(range);
            break;
        }
    }
    let chosen = chosen.ok_or_else(|| {
        ApiError::new(
            StatusCode::CONFLICT,
            "No unused default private range is available; configure a private range",
        )
    })?;
    let document = doc! {"_id":owner,"cidr":chosen.cidr(),"dns_suffix":"phub"};
    app.collection("private_networks")
        .insert_one(document.clone())
        .await?;
    Ok(document)
}

pub async fn save(app: &App, owner: &str, network: Network, suffix: &str) -> ApiResult<()> {
    let _guard = app.private_network_lock.lock().await;
    #[cfg(feature="private-sparse")]
    let _workspace_guard=crate::private_renumber::fence::stable_with_allocation(app,mongodb::bson::oid::ObjectId::parse_str(owner).map_err(|_|ApiError::bad_request("Invalid workspace"))?).await?;
    let (ranges, addresses) = occupied(app, owner).await?;
    let unchanged = app
        .collection("private_networks")
        .find_one(doc! {"_id":owner})
        .await?
        .and_then(|value| enrollment::preferences(&value).ok())
        .is_some_and(|(current, _)| current.cidr() == network.cidr());
    if !unchanged && !available(network, &ranges, &addresses) {
        return Err(ApiError::new(StatusCode::CONFLICT,
            "This private range overlaps another tenant's network or assigned addresses; choose a different range"));
    }
    app.collection("private_networks").update_one(doc! {"_id":owner},
        doc! {"$set":{"cidr":network.cidr(),"dns_suffix":suffix,"updated_at":mongodb::bson::DateTime::now()}})
        .upsert(true).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ranges_reject_equal_nested_and_retained_addresses_but_allow_adjacent() {
        let existing = Network::parse("10.203.0.0/24").unwrap();
        for cidr in ["10.203.0.0/24", "10.203.0.0/16", "10.203.0.16/28"] {
            assert!(!available(Network::parse(cidr).unwrap(), &[existing], &[]));
        }
        assert!(available(
            Network::parse("10.203.1.0/24").unwrap(),
            &[existing],
            &[]
        ));
        assert!(!available(
            Network::parse("192.168.1.0/24").unwrap(),
            &[],
            &["192.168.1.42".parse().unwrap()]
        ));
    }

    #[test]
    fn growth_crosses_octets_and_reports_unique_capacity() {
        let old = Network::parse("10.203.0.0/24").unwrap();
        let expanded = old.parent().unwrap();
        assert_eq!(expanded.cidr(), "10.203.0.0/23");
        let used: HashSet<_> = (1..=254).map(|n| format!("10.203.0.{n}")).collect();
        let next: Ipv4Addr = expanded
            .available_address("new-machine", &used)
            .unwrap()
            .parse()
            .unwrap();
        assert!(!used.contains(&next.to_string()));
        assert!(expanded.contains(next));
        assert!(Network::parse("10.203.0.0/16").unwrap().parent().is_none());
        let value = describe(
            &doc! {"cidr":"10.203.0.0/23", "additional_cidrs":["10.203.0.0/24","172.16.0.0/24"]},
        )
        .map_err(|error| error.detail.to_string())
        .unwrap();
        assert_eq!(value["address_capacity"], 510 + 254);
        assert_eq!(value["auto_expand"], true);
    }
}

#[cfg(feature="private-sparse")]
pub(crate) async fn validate_migration_targets_locked(app:&App,owner:&str,targets:&[Network])->ApiResult<()> {
    let (foreign,addresses)=occupied(app,owner).await?;
    let lans=workspace_lans(app,owner).await?;
    let current=app.collection("private_networks").find_one(doc!{"_id":owner}).await?
        .map(|row|pools(&row)).transpose()?.unwrap_or_else(||vec![Network::parse("10.203.0.0/24").expect("default")]);
    if targets.iter().any(|n|!available(*n,&foreign,&addresses)||!avoids_lans(*n,&lans)||current.iter().any(|old|old.overlaps(*n))) {
        return Err(ApiError::new(StatusCode::CONFLICT,"Migration pool conflicts with a reserved workspace, retained address, or reported local network"));
    }
    Ok(())
}

/// Rare automatic collision repair, under the existing allocation lock. Choose
/// disjoint pools ourselves; client reports contain no proposed addresses.
#[cfg(feature="private-sparse")]
pub(crate) async fn migration_targets_locked(app:&App,owner:&str,count:usize,blocked:&[mongodb::bson::Bson])->ApiResult<Vec<Network>>{
    if count==0||count>65536||blocked.len()>porthub_network::capture_routes::MAX_CAPTURE_PREFIXES{return Err(ApiError::bad_request("Invalid native repair capacity"));}
    let (mut reserved,addresses)=occupied(app,owner).await?;
    let current=ensure_locked(app,owner).await?;reserved.extend(pools(&current)?);
    let mut lans=workspace_lans(app,owner).await?;
    for value in blocked{let raw=value.as_str().ok_or_else(||ApiError::bad_request("Invalid native repair prefix"))?;lans.push(raw.parse().map_err(|_|ApiError::bad_request("Invalid native repair prefix"))?);}
    let mut remaining=count;let mut selected=Vec::new();
    while remaining>0{
        if selected.len()>=32{return Err(ApiError::new(StatusCode::CONFLICT,"No bounded disjoint address capacity is available"));}
        let required=remaining.min(65534).saturating_add(2).next_power_of_two();
        let prefix=(32-required.trailing_zeros()).clamp(16,24)as u8;
        let mut seen=HashSet::new();
        let candidate=overflow_candidates().map(|mut candidate|{while candidate.bits_for_migration()>prefix{candidate=candidate.parent().expect("bounded parent");}candidate})
            .find(|candidate|seen.insert(candidate.cidr())&&available(*candidate,&reserved,&addresses)&&avoids_lans(*candidate,&lans))
            .ok_or_else(||ApiError::new(StatusCode::CONFLICT,"No non-conflicting private range is available; existing identities are preserved"))?;
        remaining=remaining.saturating_sub(candidate.capacity()as usize);reserved.push(candidate);selected.push(candidate);
    }Ok(selected)
}
