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
use std::net::Ipv4Addr;

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
        ranges.push(enrollment::preferences(&network)?.0);
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
    Ok((ranges, addresses))
}

fn available(candidate: Network, ranges: &[Network], addresses: &[Ipv4Addr]) -> bool {
    !ranges.iter().any(|range| candidate.overlaps(*range))
        && !addresses.iter().any(|ip| candidate.contains(*ip))
}

pub async fn ensure(app: &App, owner: &str) -> ApiResult<Document> {
    let _guard = app.private_network_lock.lock().await;
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
    // Prefer the historic default, then walk the private 10/8 space in /24s.
    // Legacy tenants retain their default even if historical ranges overlap.
    for offset in 0..65536u32 {
        let index = (203 * 256 + offset) % 65536;
        let range = Network::parse(&format!("10.{}.{}.0/24", index / 256, index % 256))
            .expect("private /24");
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
}
