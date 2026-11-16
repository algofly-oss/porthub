//! Roll-forward executor for an already complete, fenced immutable journal.
//! No public route or automatic trigger calls this module.
use super::{fence, journal};
use crate::{
    error::{ApiError, ApiResult},
    App,
};
use axum::http::StatusCode;
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, Bson, Document};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
fn conflict(message: &str) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, message)
}
pub(super) fn decode(row: &Document) -> ApiResult<super::recovery::Assignment> {
    let text = |field: &str| {
        row.get_str(field)
            .map(str::to_owned)
            .map_err(|_| conflict("Invalid immutable migration row"))
    };
    let number = |field: &str| {
        row.get_i64(field)
            .ok()
            .filter(|v| *v >= 0)
            .map(|v| v as u64)
            .ok_or_else(|| conflict("Invalid migration row generation"))
    };
    Ok(super::recovery::Assignment {
        peer: text("peer")?,
        machine: text("machine")?,
        workspace: text("workspace")?,
        credential_generation: text("credential_generation")?,
        old: text("old")?
            .parse()
            .map_err(|_| conflict("Invalid old address"))?,
        new: text("new")?
            .parse()
            .map_err(|_| conflict("Invalid new address"))?,
        previous_generation: number("previous_generation")?,
        generation: number("generation")?,
    })
}
/// First pass validates the ENTIRE immutable journal before a single peer write.
/// Progress cursors never authorize skipping validation or assuming an update.
pub(super) async fn verify(
    app: &App,
    owner: ObjectId,
    job: &str,
    head: &Document,
) -> ApiResult<Vec<[u8; 32]>> {
    let count = head
        .get_i64("count")
        .ok()
        .filter(|n| *n > 0 && *n <= 65536)
        .ok_or_else(|| conflict("Invalid migration count"))?;
    let generation = head
        .get_i64("generation")
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| conflict("Invalid migration generation"))? as u64;
    let mut cursor = app
        .collection("private_renumber_assignments")
        .find(doc! {"job":job})
        .sort(doc! {"index":1})
        .batch_size(256)
        .await?;
    let mut seen = 0_i64;
    let mut peers = BTreeSet::new();
    let mut ips = BTreeSet::new();
    let mut hash = Sha256::new();
    let mut pins = Vec::new();
    while let Some(stored) = cursor.try_next().await? {
        if seen >= count
            || stored.get_i64("index").ok() != Some(seen)
            || stored.get_str("_id").ok() != Some(format!("{job}:{seen:05}").as_str())
        {
            return Err(conflict("Migration row sequence changed"));
        }
        let row = decode(&stored)?;
        if !super::recovery::validate_chunk(std::slice::from_ref(&row))
            || row.workspace != owner.to_hex()
            || row.generation != generation
            || !peers.insert(row.peer.clone())
            || !ips.insert(row.new)
        {
            return Err(conflict("Migration row identity or address conflicts"));
        }
        let bytes = mongodb::bson::to_vec(&journal::assignment_doc(&row))
            .map_err(|_| conflict("Invalid migration encoding"))?;
        pins.push(Sha256::digest(&bytes).into());
        hash.update((bytes.len() as u32).to_be_bytes());
        hash.update(bytes);
        seen += 1;
    }
    if seen != count
        || head.get_str("digest").ok() != Some(format!("{:x}", hash.finalize()).as_str())
    {
        return Err(conflict("Migration journal is incomplete or altered"));
    }
    Ok(pins)
}
#[derive(Clone, Copy, Default)]
pub(super) enum Fault {
    #[default]
    None,
    #[cfg(test)]
    AfterPeerBeforeProgress(usize),
}
/// Caller cannot bypass the monotonic old-authority drain. A resumed process
/// waits again: wall-clock timestamps/cursors never prove the old lease elapsed.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    AppliedFenced,
}
pub(super) async fn run(app: &App, owner: ObjectId, job: &str, fault: Fault) -> ApiResult<Outcome> {
    let guard = fence::exclusive(app, owner).await?;
    let heads = journal::durable(app, "private_renumber_heads");
    let head = heads
        .find_one(doc! {"_id":owner.to_hex(),"job":job})
        .await?
        .ok_or_else(|| conflict("Owned migration head not found"))?;
    if head.get_str("state").ok() != Some("applying") {
        return Err(conflict("Migration is not ready for application"));
    }
    let pins = verify(app, owner, job, &head).await?;
    let generation = head
        .get_i64("generation")
        .map_err(|_| conflict("Invalid migration generation"))?;
    let targets = head
        .get_array("target_cidrs")
        .map_err(|_| conflict("Missing migration reservations"))?
        .iter()
        .map(|v| {
            v.as_str()
                .ok_or_else(|| conflict("Invalid migration reservation"))
        })
        .collect::<ApiResult<Vec<_>>>()?;
    let parsed = targets
        .iter()
        .map(|s| crate::domain::enrollment::Network::parse(s).map_err(ApiError::bad_request))
        .collect::<ApiResult<Vec<_>>>()?;
    crate::domain::private_networks::validate_migration_targets_locked(
        app,
        &owner.to_hex(),
        &parsed,
    )
    .await?;
    app.private_relay
        .workspace_generation(&owner.to_hex(), generation as u64, true);
    // Existing signed snapshots/base/pair authority are15s. No new old-generation
    // admission can publish while this exclusive guard and durable head exist.
    tokio::time::sleep(std::time::Duration::from_secs(16)).await;
    let peers = journal::durable(app, "private_peers");
    let mut rows = app
        .collection("private_renumber_assignments")
        .find(doc! {"job":job})
        .sort(doc! {"index":1})
        .batch_size(256)
        .await?;
    let mut applied = 0_i64;
    while let Some(stored) = rows.try_next().await? {
        let row = decode(&stored)?;
        let bytes = mongodb::bson::to_vec(&journal::assignment_doc(&row))
            .map_err(|_| conflict("Invalid migration row encoding"))?;
        let observed: [u8; 32] = Sha256::digest(&bytes).into();
        if stored.get_i64("index").ok() != Some(applied)
            || pins.get(applied as usize) != Some(&observed)
        {
            return Err(conflict("Immutable migration row changed after validation"));
        }

        let machine = ObjectId::parse_str(&row.machine)
            .map_err(|_| conflict("Invalid migration machine identity"))?;
        let current = peers
            .find_one(doc! {"_id":&row.peer,"workspace_id":owner,"machine_id":machine})
            .await?
            .ok_or_else(|| conflict("Migration peer was deleted or replaced; recovery required"))?;
        if current.get_str("enrollment_generation").unwrap_or("legacy") != row.credential_generation
        {
            return Err(conflict("Migration enrollment was replaced"));
        }
        let already = current.get_str("ip").ok() == Some(row.new.to_string().as_str())
            && current.get_i64("address_generation").ok() == Some(generation);
        if !already {
            let valid_old = current.get_str("ip").ok() == Some(row.old.to_string().as_str())
                && current
                    .get_i64("address_generation")
                    .map_or(!current.contains_key("address_generation"), |v| {
                        v == row.previous_generation as i64
                    });
            if !valid_old {
                return Err(conflict("Migration peer assignment changed"));
            }
            let mut filter = doc! {"_id":&row.peer,"workspace_id":owner,"machine_id":machine,"ip":row.old.to_string()};
            for field in [
                "enrollment_generation",
                "address_generation",
                "credential_hash",
            ] {
                filter.insert(
                    field,
                    current
                        .get(field)
                        .cloned()
                        .unwrap_or_else(|| Bson::Document(doc! {"$exists":false})),
                );
            }
            let changed = peers
                .update_one(
                    filter,
                    doc! {"$set":{"ip":row.new.to_string(),"address_generation":generation}},
                )
                .await?;
            if changed.matched_count != 1 {
                return Err(conflict("Migration peer changed during address CAS"));
            }
        }
        applied += 1;
        #[cfg(test)]
        if matches!(fault,Fault::AfterPeerBeforeProgress(n) if n==applied as usize) {
            return Err(conflict("Injected crash after peer write before progress"));
        }
        #[cfg(not(test))]
        let _ = fault;
        let progress=heads.update_one(doc!{"_id":owner.to_hex(),"job":job,"generation":generation,"state":"applying","digest":head.get("digest")},doc!{"$set":{"applied":applied}}).await?;
        if progress.matched_count != 1 {
            return Err(conflict(
                "Migration ownership changed during progress checkpoint",
            ));
        }
    }
    if head.get_i64("count").ok() != Some(applied) {
        return Err(conflict("Migration assignment count changed"));
    }
    // Final full membership verification also detects newly inserted/deleted rows
    // and preserves disabled/revoked status and all unrelated document fields.
    let actual = peers.count_documents(doc! {"workspace_id":owner}).await?;
    let complete = peers
        .count_documents(doc! {"workspace_id":owner,"address_generation":generation})
        .await?;
    if actual != applied as u64 || complete != actual {
        return Err(conflict("Workspace membership changed during migration"));
    }
    // Pool/head publication remains deliberately fenced until a CAS of the exact
    // old preferences and directory invalidation are implemented together.
    drop(guard);
    Ok(Outcome::AppliedFenced)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI; two real16s authority drains"]
    async fn standalone_crash_after_peer_before_cursor_rolls_forward_without_recreating_credentials(
    ) -> anyhow::Result<()> {
        let client =
            mongodb::Client::with_uri_str(std::env::var("PORTHUB_TEST_MONGO_URI")?).await?;
        let db = client.database(&format!(
            "porthub_renumber_apply_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let result=async {
            let owner=ObjectId::new();let mut rows=Vec::new();let mut before=Vec::new();let job="1123456789abcdef0123456789abcdef";
            let app=App::new(crate::config::Config::default(),db.clone());
            for i in 0..2_u8 {
                let machine=ObjectId::new();let id=format!("{owner}:{machine}");
                let row=super::super::recovery::Assignment{peer:id.clone(),machine:machine.to_hex(),workspace:owner.to_hex(),credential_generation:"enrollment-1".into(),old:std::net::Ipv4Addr::new(10,203,0,i+1),new:std::net::Ipv4Addr::new(10,204,0,i+1),previous_generation:0,generation:1};
                let peer=doc!{"_id":&id,"workspace_id":owner,"machine_id":machine,"owner_id":owner,"ip":row.old.to_string(),"enabled":i==0,"credential_hash":"private-fixture-hash-unchanged","enrollment_generation":"enrollment-1","custom_hostname":format!("stable-{i}"),"unrelated":{"groups":["unchanged-group"],"rule":"unchanged-book"}};
                app.collection("private_peers").insert_one(peer.clone()).await?;before.push(peer);rows.push(row);
            }
            let guard=fence::exclusive(&app,owner).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            journal::prepare(&guard,job,&rows,&["10.204.0.0/16".into()]).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;drop(guard);
            assert!(run(&app,owner,job,Fault::AfterPeerBeforeProgress(1)).await.is_err());
            let head=app.collection("private_renumber_heads").find_one(doc!{"_id":owner.to_hex()}).await?.unwrap();
            assert!(!head.contains_key("applied"),"injected crash accidentally acknowledged cursor");
            let first=app.collection("private_peers").find_one(doc!{"_id":&rows[0].peer}).await?.unwrap();assert_eq!(first.get_str("ip")?,rows[0].new.to_string());
            drop(app);
            let reopened=App::new(crate::config::Config::default(),db.clone());
            assert!(fence::stable(&reopened,owner).await.is_err());
            assert_eq!(run(&reopened,owner,job,Fault::None).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?,Outcome::AppliedFenced);
            for (row,mut expected) in rows.iter().zip(before) {
                expected.insert("ip",row.new.to_string());expected.insert("address_generation",1_i64);
                assert_eq!(reopened.collection("private_peers").find_one(doc!{"_id":&row.peer}).await?.unwrap(),expected,"migration changed identity, credentials, hostname, policy, or disabled status");
            }
            let head=reopened.collection("private_renumber_heads").find_one(doc!{"_id":owner.to_hex()}).await?.unwrap();assert_eq!(head.get_i64("applied")?,2);assert_eq!(head.get_str("state")?,"applying");
            assert!(fence::stable(&reopened,owner).await.is_err(),"unfinished finalization prematurely authorized a mixed generation");
            Ok::<_,anyhow::Error>(())
        }.await;
        db.drop().await?;
        result
    }
}
