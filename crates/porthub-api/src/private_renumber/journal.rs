//! Durable single-document migration journal operations. No endpoint or runner
//! exposes these operations until reservation and authority-drain wiring is complete.
use super::recovery::{validate_chunk, Assignment};
use crate::{
    error::{ApiError, ApiResult},
    App,
};
use axum::http::StatusCode;
use futures_util::TryStreamExt;
use mongodb::{
    bson::{doc, Document},
    options::{Acknowledgment, CollectionOptions, WriteConcern},
    Collection,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
fn conflict(message: &str) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, message)
}
pub(super) fn durable(app: &App, name: &str) -> Collection<Document> {
    app.db.collection_with_options(
        name,
        CollectionOptions::builder()
            .write_concern(
                WriteConcern::builder()
                    .w(Acknowledgment::Nodes(1))
                    .journal(true)
                    .build(),
            )
            .build(),
    )
}
pub(super) async fn indexes(app:&App)->ApiResult<()> {
    app.private_sparse.renumber_indexes.get_or_try_init(||async {
        durable(app,"private_renumber_heads").create_index(mongodb::IndexModel::builder().keys(doc!{"state":1,"_id":1}).build()).await?;
        durable(app,"private_renumber_assignments").create_index(mongodb::IndexModel::builder().keys(doc!{"job":1,"index":1}).options(mongodb::options::IndexOptions::builder().unique(true).build()).build()).await?;
        durable(app,"private_renumber_assignments").create_index(mongodb::IndexModel::builder().keys(doc!{"workspace":1,"job":1}).build()).await?;
        Ok::<_,ApiError>(())
    }).await?;Ok(())
}
pub(super) fn assignment_doc(row: &Assignment) -> Document {
    doc! {"peer":&row.peer,"machine":&row.machine,"workspace":&row.workspace,
    "credential_generation":&row.credential_generation,"old":row.old.to_string(),"new":row.new.to_string(),
    "previous_generation":row.previous_generation as i64,"generation":row.generation as i64}
}
/// Canonical digest of ALL immutable rows. Never compute this from a progress
/// cursor or from whichever partial records happened to survive a crash.
pub fn plan_digest(rows: &[Assignment]) -> ApiResult<String> {
    if rows.is_empty() || rows.len() > 65536 {
        return Err(conflict("Migration assignment count exceeds bounds"));
    }
    let mut peers = BTreeSet::new();
    let mut addresses = BTreeSet::new();
    let mut hash = Sha256::new();
    let first = &rows[0];
    for chunk in rows.chunks(256) {
        if !validate_chunk(chunk) {
            return Err(conflict("Invalid migration assignment chunk"));
        }
        for row in chunk {
            if row.workspace != first.workspace
                || row.generation != first.generation
                || row.previous_generation != first.previous_generation
                || row.generation > i64::MAX as u64
                || [
                    &row.peer,
                    &row.machine,
                    &row.workspace,
                    &row.credential_generation,
                ]
                .iter()
                .any(|s| s.len() > 128)
                || !peers.insert(&row.peer)
                || !addresses.insert(row.new)
            {
                return Err(conflict(
                    "Migration assignment identity, target, or generation conflicts",
                ));
            }
            let bytes = mongodb::bson::to_vec(&assignment_doc(row))
                .map_err(|_| conflict("Invalid assignment encoding"))?;
            hash.update((bytes.len() as u32).to_be_bytes());
            hash.update(bytes);
        }
    }
    Ok(format!("{:x}", hash.finalize()))
}
/// A head becomes fenced only AFTER its complete immutable plan is staged, and
/// BEFORE any peer address can be written. Uncertain write results
/// must be reconciled by exact fresh reads; they are never rolled back implicitly.
/// Caller must hold allocation and workspace publication guards.
#[derive(Clone, Copy, Default)]
pub(super) enum Fault {
    #[default]
    None,
    #[cfg(test)]
    AfterStagedRow(usize),
}
pub(super) async fn prepare(
    guard: &super::fence::Exclusive<'_>,
    job: &str,
    rows: &[Assignment],
    target_cidrs: &[String],
    reporting_peer: Option<&str>,
) -> ApiResult<()> {
    prepare_with_fault(guard, job, rows, target_cidrs, reporting_peer, Fault::None).await
}
async fn prepare_with_fault(
    guard: &super::fence::Exclusive<'_>,
    job: &str,
    rows: &[Assignment],
    target_cidrs: &[String],
    reporting_peer: Option<&str>,
    fault: Fault,
) -> ApiResult<()> {
    if job.len() != 32
        || !job
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || target_cidrs.is_empty()
        || target_cidrs.len() > 32
    {
        return Err(conflict("Invalid migration job or reserved pools"));
    }
    guard.require_allocation()?;
    indexes(guard.app).await?;
    let digest = plan_digest(rows)?;
    let first = &rows[0];
    let app = guard.app;
    if first.workspace != guard.workspace.to_hex() {
        return Err(conflict("Migration guard belongs to a different workspace"));
    }

    let parsed: Vec<_> = target_cidrs
        .iter()
        .map(|s| crate::domain::enrollment::Network::parse(s).map_err(ApiError::bad_request))
        .collect::<ApiResult<_>>()?;
    for (i, pool) in parsed.iter().enumerate() {
        if pool.cidr() != target_cidrs[i]
            || parsed.iter().take(i).any(|other| pool.overlaps(*other))
        {
            return Err(conflict("Migration pools must be canonical and disjoint"));
        }
    }
    if rows.iter().any(|row| {
        !parsed.iter().any(|p| p.contains(row.new)) || parsed.iter().any(|p| p.contains(row.old))
    }) {
        return Err(conflict(
            "Migration requires fresh disjoint target address pools",
        ));
    }
    crate::domain::private_networks::validate_migration_targets_locked(
        app,
        &first.workspace,
        &parsed,
    )
    .await?;
    // Full inventory equality, not a selected subset: unenlisted/removed or
    // replaced peers cannot be silently skipped. A resumed Applying job accepts
    // only its exact new-generation assignment, never a coincidental new IP.
    let mut expected: std::collections::HashMap<_, _> =
        rows.iter().map(|row| (row.peer.as_str(), row)).collect();
    let mut inventory=app.collection("private_peers").find(doc!{"workspace_id":guard.workspace}).projection(doc!{"_id":1,"machine_id":1,"workspace_id":1,"ip":1,"enrollment_generation":1,"address_generation":1}).batch_size(256).await?;
    while let Some(peer) = inventory.try_next().await? {
        let id = peer
            .get_str("_id")
            .map_err(|_| conflict("Invalid migration peer identity"))?;
        let row = expected
            .remove(id)
            .ok_or_else(|| conflict("Workspace membership changed while staging migration"))?;
        if crate::store::id(peer.get("machine_id")) != row.machine
            || peer.get_str("enrollment_generation").unwrap_or("legacy")
                != row.credential_generation
        {
            return Err(conflict(
                "Migration peer identity or enrollment was replaced",
            ));
        }
        let ip = peer.get_str("ip").unwrap_or("");
        let old = ip == row.old.to_string()
            && peer
                .get_i64("address_generation")
                .map_or(!peer.contains_key("address_generation"), |g| {
                    g == row.previous_generation as i64
                });
        let applied = ip == row.new.to_string()
            && peer.get_i64("address_generation").ok() == Some(row.generation as i64);
        if !old && !applied {
            return Err(conflict("Migration peer address or generation changed"));
        }
    }
    if !expected.is_empty() {
        return Err(conflict(
            "Migration peer was deleted; explicit recovery is required",
        ));
    }
    let previous = app
        .collection("private_networks")
        .find_one(doc! {"_id":&first.workspace})
        .await?;
    let mut previous_fields = Document::new();
    if let Some(previous) = &previous {
        for field in [
            "cidr",
            "additional_cidrs",
            "dns_suffix",
            "_renumber_job",
            "_address_generation",
        ] {
            if let Some(value) = previous.get(field) {
                previous_fields.insert(field, value.clone());
            }
        }
    }
    if mongodb::bson::to_vec(&previous_fields)
        .map_err(|_| conflict("Invalid previous preferences"))?
        .len()
        > 16384
    {
        return Err(conflict(
            "Previous private preferences exceed migration journal bounds",
        ));
    }
    let previous_preferences = doc! {"existed":previous.is_some(),"fields":previous_fields};
    let heads = durable(app, "private_renumber_heads");
    // Historical generation zero is explicit before the CAS. A duplicate insert
    // is tolerated only by reading and checking the existing head below.
    if heads
        .find_one(doc! {"_id":&first.workspace})
        .await?
        .is_none()
    {
        if let Err(error) = heads
            .insert_one(doc! {"_id":&first.workspace,"generation":0_i64,"state":"stable"})
            .await
        {
            if heads
                .find_one(doc! {"_id":&first.workspace})
                .await?
                .is_none()
            {
                return Err(error.into());
            }
        }
    }
    let initial = heads
        .find_one(doc! {"_id":&first.workspace})
        .await?
        .ok_or_else(|| conflict("Migration head disappeared"))?;
    let idle = initial.get_str("state").ok() == Some("stable")
        && initial.get_i64("generation").ok() == Some(first.previous_generation as i64);
    let resume = initial.get_str("state").ok() == Some("applying")
        && initial.get_i64("plan_version").ok() == Some(2)
        && initial.get_str("job").ok() == Some(job)
        && initial.get_str("digest").ok() == Some(digest.as_str());
    if !idle && !resume {
        return Err(conflict(
            "Another migration owns this workspace or prototype recovery version is unsupported",
        ));
    }
    // Both allocation/publication guards remain held while staging. Until the
    // complete immutable plan is journaled, head stays Stable and no peer writes
    // are possible. A crash leaves ONLY inert orphan rows, never a partial active
    // migration or a reservation capable of authorizing address changes.
    let assignments = durable(app, "private_renumber_assignments");
    for (index, row) in rows.iter().enumerate() {
        let id = format!("{job}:{index:05}");
        let mut immutable = assignment_doc(row);
        immutable.insert("_id", &id);
        immutable.insert("job", job);
        immutable.insert("index", index as i64);
        if reporting_peer == Some(row.peer.as_str()) {
            // The queue is consumed after activation. Keep the authenticated
            // reporter on its existing immutable peer/old-address record.
            immutable.insert("reported_native_collision", true);
        }
        assignments
            .update_one(doc! {"_id":&id}, doc! {"$setOnInsert":&immutable})
            .upsert(true)
            .await?;
        let stored = assignments
            .find_one(doc! {"_id":&id})
            .await?
            .ok_or_else(|| conflict("Migration assignment disappeared"))?;
        // Progress lives elsewhere; assignment rows are immutable exact bytes.
        if stored != immutable {
            return Err(conflict("Migration assignment was replaced or changed"));
        }
        #[cfg(test)]
        if matches!(fault,Fault::AfterStagedRow(n) if n==index+1) {
            return Err(conflict("Injected crash before complete plan activation"));
        }
        #[cfg(not(test))]
        let _ = fault;
    }
    super::retirement::stage(app,job,rows,previous.as_ref()).await?;
    // One atomic head CAS activates BOTH the complete plan and its target pool
    // reservation. No per-peer mutation can precede this durable fence.
    let transition=heads.update_one(doc!{"_id":&first.workspace,"generation":first.previous_generation as i64,"state":"stable"},
        doc!{"$set":{"generation":first.generation as i64,"state":"applying","plan_version":2_i64,"job":job,"digest":&digest,"count":rows.len() as i64,"target_cidrs":target_cidrs.to_vec(),"previous_preferences":previous_preferences}}).await;
    // Even a write-concern timeout may have committed. Never claim failure means
    // unchanged state; exact persisted ownership is the only recovery authority.
    let head = heads
        .find_one(doc! {"_id":&first.workspace})
        .await?
        .ok_or_else(|| conflict("Migration head disappeared"))?;
    if head.get_str("job").ok() != Some(job)
        || head.get_str("digest").ok() != Some(digest.as_str())
        || head.get_i64("generation").ok() != Some(first.generation as i64)
        || head.get_i64("count").ok() != Some(rows.len() as i64)
        || head.get_array("target_cidrs").ok()
            != Some(&target_cidrs.iter().cloned().map(Into::into).collect())
    {
        return match transition {
            Err(error) => Err(error.into()),
            Ok(_) => Err(conflict("Another migration owns this workspace")),
        };
    }
    if head.get_str("state").ok() != Some("applying")
        || head.get_i64("plan_version").ok() != Some(2)
    {
        return Err(conflict("Migration head is not resumable"));
    }
    super::retirement::activate(app,guard.workspace,job).await?;
    app.private_relay
        .workspace_generation(&first.workspace, first.generation, true);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn row(i: u32) -> Assignment {
        Assignment {
            peer: format!("peer-{i}"),
            machine: format!("machine-{i}"),
            workspace: "workspace".into(),
            credential_generation: "enrollment-1".into(),
            old: std::net::Ipv4Addr::from(0x0acb0001 + i),
            new: std::net::Ipv4Addr::from(0x0acc0001 + i),
            previous_generation: 0,
            generation: 1,
        }
    }
    #[test]
    fn full_plan_uniqueness_crosses_chunk_boundaries() {
        let mut rows = (0..257).map(row).collect::<Vec<_>>();
        assert!(plan_digest(&rows).is_ok());
        rows[256].new = rows[0].new;
        assert!(plan_digest(&rows).is_err());
    }
    #[test]
    fn digest_binds_order_identity_and_both_addresses() {
        let a = vec![row(0), row(1)];
        let original = plan_digest(&a).ok().unwrap();
        let mut b = a.clone();
        b.reverse();
        assert_ne!(plan_digest(&b).ok().unwrap(), original);
        b = a.clone();
        b[0].old = std::net::Ipv4Addr::new(10, 203, 5, 2);
        assert_ne!(plan_digest(&b).ok().unwrap(), original);
    }
    #[test]
    fn generations_cannot_wrap_signed_storage() {
        let mut a = row(0);
        a.previous_generation = i64::MAX as u64;
        a.generation = a.previous_generation + 1;
        assert!(plan_digest(&[a]).is_err());
    }
    #[tokio::test]
    #[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
    async fn journaled_prepare_reopens_idempotently_and_foreign_targets_stay_reserved(
    ) -> anyhow::Result<()> {
        let client =
            mongodb::Client::with_uri_str(std::env::var("PORTHUB_TEST_MONGO_URI")?).await?;
        let db = client.database(&format!(
            "porthub_renumber_prepare_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let result=async {
            let owner=mongodb::bson::oid::ObjectId::new();let machine=mongodb::bson::oid::ObjectId::new();
            let mut row=row(0);row.workspace=owner.to_hex();row.machine=machine.to_hex();
            let job="0123456789abcdef0123456789abcdef";
            let app=App::new(crate::config::Config::default(),db.clone());
            app.collection("private_peers").insert_one(doc!{"_id":&row.peer,"workspace_id":owner,"machine_id":machine,"ip":row.old.to_string(),"enrollment_generation":&row.credential_generation,"enabled":true,"credential_hash":"unchanged-private-fixture-hash"}).await?;
            let before=app.collection("private_peers").find_one(doc!{"_id":&row.peer}).await?.unwrap();
            let pools=vec!["10.204.0.0/16".to_owned()];
            let guard=super::super::fence::exclusive(&app,owner).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            prepare(&guard,job,&[row.clone()],&pools,None).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            drop(guard);drop(app);
            // New App has no process-local fence or Hub state. Durable Applying
            // still refuses ordinary private publication after restart.
            let reopened=App::new(crate::config::Config::default(),db.clone());
            assert!(super::super::fence::stable(&reopened,owner).await.is_err());
            let guard=super::super::fence::exclusive(&reopened,owner).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            prepare(&guard,job,&[row.clone()],&pools,None).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            assert!(prepare(&guard,"1123456789abcdef0123456789abcdef",&[row.clone()],&pools,None).await.is_err());
            drop(guard);
            let other=mongodb::bson::oid::ObjectId::new().to_hex();
            let conflict=crate::domain::private_networks::validate_migration_targets_locked(&reopened,&other,&[crate::domain::enrollment::Network::parse("10.204.0.0/16").unwrap()]).await;
            assert!(conflict.is_err(),"pending reservation was invisible to another tenant");
            let after=reopened.collection("private_peers").find_one(doc!{"_id":&row.peer}).await?.unwrap();assert_eq!(before,after,"preparation changed a peer or credential");
            let assignments=reopened.collection("private_renumber_assignments");
            assignments.update_one(doc!{"job":job},doc!{"$set":{"new":"10.204.5.99"}}).await?;
            let guard=super::super::fence::exclusive(&reopened,owner).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            assert!(prepare(&guard,job,&[row],&pools,None).await.is_err(),"changed immutable row adopted");
            Ok::<_,anyhow::Error>(())
        }.await;
        db.drop().await?;
        result
    }
    #[tokio::test]
    #[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
    async fn crash_during_inert_staging_never_activates_partial_plan_or_reserves_targets(
    ) -> anyhow::Result<()> {
        let client =
            mongodb::Client::with_uri_str(std::env::var("PORTHUB_TEST_MONGO_URI")?).await?;
        let db = client.database(&format!(
            "porthub_renumber_stage_crash_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let result=async {
            let owner=mongodb::bson::oid::ObjectId::new();let mut rows=Vec::new();let job="3123456789abcdef0123456789abcdef";
            let app=App::new(crate::config::Config::default(),db.clone());
            for i in 0..2 {let machine=mongodb::bson::oid::ObjectId::new();let mut value=row(i);value.machine=machine.to_hex();value.workspace=owner.to_hex();app.collection("private_peers").insert_one(doc!{"_id":&value.peer,"workspace_id":owner,"machine_id":machine,"ip":value.old.to_string(),"enrollment_generation":&value.credential_generation}).await?;rows.push(value);}
            let pools=vec!["10.204.0.0/16".to_owned()];
            let guard=super::super::fence::exclusive(&app,owner).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            assert!(prepare_with_fault(&guard,job,&rows,&pools,None,Fault::AfterStagedRow(1)).await.is_err());drop(guard);drop(app);
            let reopened=App::new(crate::config::Config::default(),db.clone());
            let head=reopened.collection("private_renumber_heads").find_one(doc!{"_id":owner.to_hex()}).await?.unwrap();assert_eq!(head.get_str("state")?,"stable");assert_eq!(head.get_i64("generation")?,0);assert!(!head.contains_key("job"));
            assert!(super::super::fence::stable(&reopened,owner).await.is_ok(),"incomplete inert rows fenced a workspace after restart");
            assert_eq!(reopened.collection("private_renumber_assignments").count_documents(doc!{"job":job}).await?,1);
            let other=mongodb::bson::oid::ObjectId::new().to_hex();let target=crate::domain::enrollment::Network::parse(&pools[0]).unwrap();
            assert!(crate::domain::private_networks::validate_migration_targets_locked(&reopened,&other,&[target]).await.is_ok(),"inert staging incorrectly reserved an address pool");
            reopened.collection("private_networks").insert_one(doc!{"_id":&other,"cidr":&pools[0],"dns_suffix":"other.private"}).await?;
            let guard=super::super::fence::exclusive(&reopened,owner).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            assert!(prepare(&guard,job,&rows,&pools,None).await.is_err(),"restart ignored newly acquired foreign reservation");drop(guard);
            assert_eq!(reopened.collection("private_renumber_heads").find_one(doc!{"_id":owner.to_hex()}).await?.unwrap().get_str("state")?,"stable");
            reopened.collection("private_networks").delete_one(doc!{"_id":&other,"cidr":&pools[0]}).await?;
            let guard=super::super::fence::exclusive(&reopened,owner).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            prepare(&guard,job,&rows,&pools,None).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;drop(guard);
            let head=reopened.collection("private_renumber_heads").find_one(doc!{"_id":owner.to_hex()}).await?.unwrap();assert_eq!(head.get_str("state")?,"applying");assert_eq!(head.get_i64("plan_version")?,2);
            assert_eq!(super::super::apply::verify(&reopened,owner,job,&head).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?.len(),2);
            for row in rows {assert_eq!(reopened.collection("private_peers").find_one(doc!{"_id":&row.peer}).await?.unwrap().get_str("ip")?,row.old.to_string());}
            Ok::<_,anyhow::Error>(())
        }.await;
        db.drop().await?;
        result
    }
}
