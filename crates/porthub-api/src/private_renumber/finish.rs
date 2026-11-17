//! Exact preference/DNS/head publication after durable assignment completion.
use super::{fence, journal};
use crate::{
    error::{ApiError, ApiResult},
    App,
};
use axum::http::StatusCode;
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, Bson, Document};
fn conflict(s: &str) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, s)
}
#[derive(Clone, Copy, Default)]
pub(super) enum Fault {
    #[default]
    None,
    #[cfg(test)]
    AfterPreferences,
}
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    Committed,
    AlreadyCommitted,
}
/// A completed head is an idempotent no-op; it must never overwrite a later
/// legitimate preferences edit, enrollment, or credential revocation.
pub(super) async fn run(app: &App, owner: ObjectId, job: &str, fault: Fault) -> ApiResult<Outcome> {
    let _guard = fence::exclusive(app, owner).await?;
    let key = owner.to_hex();
    let heads = journal::durable(app, "private_renumber_heads");
    let head = heads
        .find_one(doc! {"_id":&key,"job":job})
        .await?
        .ok_or_else(|| conflict("Owned migration head not found"))?;
    let state = head
        .get_str("state")
        .map_err(|_| conflict("Invalid migration head"))?;
    if state == "stable" {
        return Ok(Outcome::AlreadyCommitted);
    }
    if !matches!(state, "applying" | "committing") {
        return Err(conflict("Migration assignments are not ready to publish"));
    }
    let generation = head
        .get_i64("generation")
        .ok()
        .filter(|g| *g > 0)
        .ok_or_else(|| conflict("Invalid migration generation"))?;
    let count = head
        .get_i64("count")
        .ok()
        .filter(|c| *c > 0 && *c <= 65536)
        .ok_or_else(|| conflict("Invalid migration count"))?;
    if head.get_i64("applied").ok() != Some(count) {
        return Err(conflict("Migration progress is incomplete"));
    }
    let pins = super::apply::verify(app, owner, job, &head).await?;
    super::retirement::activate(app,owner,job).await?;
    let mut rows = app
        .collection("private_renumber_assignments")
        .find(doc! {"job":job})
        .sort(doc! {"index":1})
        .batch_size(256)
        .await?;
    let mut verified = 0_i64;
    while let Some(stored) = rows.try_next().await? {
        let row = super::apply::decode(&stored)?;
        let bytes = mongodb::bson::to_vec(&journal::assignment_doc(&row))
            .map_err(|_| conflict("Invalid migration row encoding"))?;
        let observed: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(bytes).into();
        if stored.get_i64("index").ok() != Some(verified)
            || pins.get(verified as usize) != Some(&observed)
        {
            return Err(conflict("Immutable row changed before final publication"));
        }

        let machine = ObjectId::parse_str(&row.machine)
            .map_err(|_| conflict("Invalid migration machine identity"))?;
        let current=app.collection("private_peers").find_one(doc!{"_id":&row.peer,"workspace_id":owner,"machine_id":machine,"ip":row.new.to_string(),"address_generation":generation}).projection(doc!{"enrollment_generation":1}).await?.ok_or_else(||conflict("Assigned peer changed before publication"))?;
        if current.get_str("enrollment_generation").unwrap_or("legacy") != row.credential_generation
        {
            return Err(conflict("Enrollment changed before publication"));
        }
        verified += 1;
    }
    if verified != count
        || app
            .collection("private_peers")
            .count_documents(doc! {"workspace_id":owner})
            .await?
            != count as u64
    {
        return Err(conflict("Workspace membership changed before publication"));
    }
    let previous = head
        .get_document("previous_preferences")
        .map_err(|_| conflict("Migration lacks previous preferences; recovery required"))?;
    let previous_fields = previous
        .get_document("fields")
        .map_err(|_| conflict("Invalid previous preferences"))?;
    let existed = previous
        .get_bool("existed")
        .map_err(|_| conflict("Invalid previous preferences existence"))?;
    let targets = head
        .get_array("target_cidrs")
        .ok()
        .filter(|p| !p.is_empty() && p.len() <= 32)
        .ok_or_else(|| conflict("Invalid reserved pools"))?;
    let primary = targets[0]
        .as_str()
        .ok_or_else(|| conflict("Invalid primary migration pool"))?;
    let additional = targets[1..].to_vec();
    // This durable intent precedes the cross-document preferences write. Its
    // explicit per-document markers disambiguate an ACK lost after that write.
    if state == "applying" {
        let changed=heads.update_one(doc!{"_id":&key,"job":job,"generation":generation,"state":"applying","applied":count,"digest":head.get("digest")},doc!{"$set":{"state":"committing"}}).await?;
        if changed.matched_count != 1 {
            return Err(conflict("Migration changed before preference commit"));
        }
    }
    let preferences = journal::durable(app, "private_networks");
    let desired = doc! {"cidr":primary,"additional_cidrs":additional,"_renumber_job":job,"_address_generation":generation};
    let current = preferences.find_one(doc! {"_id":&key}).await?;
    let is_own_commit = |row: &Document| {
        desired.iter().all(|(k, v)| row.get(k) == Some(v))
            && row.get("dns_suffix") == previous_fields.get("dns_suffix")
    };
    if !current.as_ref().is_some_and(is_own_commit) {
        if existed {
            let mut filter = doc! {"_id":&key};
            for field in [
                "cidr",
                "additional_cidrs",
                "dns_suffix",
                "_renumber_job",
                "_address_generation",
            ] {
                filter.insert(
                    field,
                    previous_fields
                        .get(field)
                        .cloned()
                        .unwrap_or_else(|| Bson::Document(doc! {"$exists":false})),
                );
            }
            let changed = preferences
                .update_one(filter, doc! {"$set":&desired})
                .await?;
            if changed.matched_count != 1 {
                return Err(conflict("Private preferences changed; refuse to overwrite"));
            }
        } else {
            let mut document = desired.clone();
            document.insert("_id", &key);
            preferences.insert_one(document).await?;
        }
    }
    let readback = preferences
        .find_one(doc! {"_id":&key})
        .await?
        .ok_or_else(|| conflict("Committed preferences disappeared"))?;
    if !is_own_commit(&readback) {
        return Err(conflict(
            "Private preference readback differs from owned commit",
        ));
    }
    #[cfg(test)]
    if matches!(fault, Fault::AfterPreferences) {
        return Err(conflict(
            "Injected crash after preferences before head commit",
        ));
    }
    #[cfg(not(test))]
    let _ = fault;
    journal::durable(app, "private_name_directory_state")
        .update_one(doc! {"_id":&key}, doc! {"$set":{"ready":false}})
        .upsert(true)
        .await?;
    let changed=heads.update_one(doc!{"_id":&key,"job":job,"generation":generation,"state":"committing","applied":count,"digest":head.get("digest")},doc!{"$set":{"state":"stable"}}).await?;
    if changed.matched_count != 1 {
        return Err(conflict("Migration changed before stable publication"));
    }
    app.private_relay
        .workspace_generation(&key, generation as u64, false);
    Ok(Outcome::Committed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI; real16s authority drain"]
    async fn crash_after_preferences_recovers_exact_job_preserving_dns_rules_and_identity(
    ) -> anyhow::Result<()> {
        let client =
            mongodb::Client::with_uri_str(std::env::var("PORTHUB_TEST_MONGO_URI")?).await?;
        let db = client.database(&format!(
            "porthub_renumber_finish_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let result=async {
            let owner=ObjectId::new();let machine=ObjectId::new();let key=owner.to_hex();let id=format!("{owner}:{machine}");let job="2123456789abcdef0123456789abcdef";
            let app=App::new(crate::config::Config::default(),db.clone());
            let row=super::super::recovery::Assignment{peer:id.clone(),machine:machine.to_hex(),workspace:key.clone(),credential_generation:"enrollment-1".into(),old:"10.203.0.2".parse()?,new:"10.204.0.2".parse()?,previous_generation:0,generation:1};
            app.collection("users").insert_one(doc!{"_id":owner,"enabled":true}).await?;
            let peer=doc!{"_id":&id,"workspace_id":owner,"machine_id":machine,"owner_id":owner,"ip":row.old.to_string(),"enabled":true,"credential_hash":"unchanged-fixture-private-hash","enrollment_generation":"enrollment-1","custom_hostname":"stable-dns-name"};
            app.collection("private_peers").insert_one(peer.clone()).await?;
            app.collection("private_networks").insert_one(doc!{"_id":&key,"cidr":"10.203.0.0/24","dns_suffix":"private.test","unrelated":"preserved"}).await?;
            let policy=doc!{"_id":ObjectId::new(),"user_id":owner,"rules":[{"source":id.clone(),"deny":true}],"revision":7_i64};
            app.collection("access_rulebooks").insert_one(policy.clone()).await?;
            app.collection("private_name_directory_state").insert_one(doc!{"_id":&key,"ready":true,"generation":"old-directory"}).await?;
            let guard=fence::exclusive(&app,owner).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            journal::prepare(&guard,job,&[row.clone()],&["10.204.0.0/16".into()]).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;drop(guard);
            super::super::apply::run(&app,owner,job,super::super::apply::Fault::None).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            assert!(run(&app,owner,job,Fault::AfterPreferences).await.is_err());
            let head=app.collection("private_renumber_heads").find_one(doc!{"_id":&key}).await?.unwrap();assert_eq!(head.get_str("state")?,"committing");
            assert!(fence::stable(&app,owner).await.is_err());drop(app);
            let reopened=App::new(crate::config::Config::default(),db.clone());
            let deferred_id=ObjectId::new();let deferred_machine=doc!{"_id":deferred_id,"user_id":owner,"name":"Queued registered machine"};
            reopened.collection("machines").insert_one(deferred_machine.clone()).await?;
            crate::domain::enrollment::ensure(&reopened,&deferred_machine).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            assert!(reopened.collection("private_peers").find_one(doc!{"machine_id":deferred_id}).await?.is_none());
            assert_eq!(reopened.collection("private_renumber_deferred").count_documents(doc!{"_id":deferred_id.to_hex()}).await?,1);

            // Authoritative foreign preference edit must block recovery, not be
            // silently normalized into the old migration's desired state.
            reopened.collection("private_networks").update_one(doc!{"_id":&key},doc!{"$set":{"dns_suffix":"foreign.test"}}).await?;
            assert!(run(&reopened,owner,job,Fault::None).await.is_err());
            let current=reopened.collection("private_networks").find_one(doc!{"_id":&key}).await?.unwrap();assert_eq!(current.get_str("dns_suffix")?,"foreign.test");
            reopened.collection("private_networks").update_one(doc!{"_id":&key,"dns_suffix":"foreign.test"},doc!{"$set":{"dns_suffix":"private.test"}}).await?;
            let batch=super::super::recover::pending_once(&reopened,None).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            assert_eq!(batch.attempts.len(),1);assert_eq!(batch.attempts[0].workspace,owner);assert_eq!(batch.attempts[0].outcome,super::super::recover::Outcome::Committed);
            assert_eq!(batch.next,Some(owner));
            assert!(super::super::recover::pending_once(&reopened,batch.next).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?.attempts.is_empty());
            assert!(fence::stable(&reopened,owner).await.is_ok());
            let enrollment=super::super::deferred::pending_once(&reopened,None).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            assert_eq!(enrollment.attempted,1);assert_eq!(enrollment.completed,1);
            assert_eq!(enrollment.next,Some(deferred_id));
            let new_peer=reopened.collection("private_peers").find_one(doc!{"machine_id":deferred_id,"workspace_id":owner}).await?.unwrap();
            assert!(crate::domain::enrollment::Network::parse("10.204.0.0/16").unwrap().contains(new_peer.get_str("ip")?.parse()?));
            assert_eq!(reopened.collection("private_renumber_deferred").count_documents(doc!{"_id":deferred_id.to_hex()}).await?,0);

            let preferences=reopened.collection("private_networks").find_one(doc!{"_id":&key}).await?.unwrap();assert_eq!(preferences.get_str("cidr")?,"10.204.0.0/16");assert_eq!(preferences.get_str("dns_suffix")?,"private.test");assert_eq!(preferences.get_str("unrelated")?,"preserved");
            let mut expected_peer=peer;expected_peer.insert("ip",row.new.to_string());expected_peer.insert("address_generation",1_i64);
            assert_eq!(reopened.collection("private_peers").find_one(doc!{"_id":&id}).await?.unwrap(),expected_peer);
            assert_eq!(reopened.collection("access_rulebooks").find_one(doc!{"_id":policy.get("_id")}).await?.unwrap(),policy);
            assert!(!reopened.collection("private_name_directory_state").find_one(doc!{"_id":&key}).await?.unwrap().get_bool("ready")?);
            // Completed-job replay must not overwrite future legitimate edits.
            reopened.collection("private_networks").update_one(doc!{"_id":&key},doc!{"$set":{"dns_suffix":"later.test"}}).await?;
            assert_eq!(run(&reopened,owner,job,Fault::None).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?,Outcome::AlreadyCommitted);
            assert_eq!(reopened.collection("private_networks").find_one(doc!{"_id":&key}).await?.unwrap().get_str("dns_suffix")?,"later.test");
            Ok::<_,anyhow::Error>(())
        }.await;
        db.drop().await?;
        result
    }
}
