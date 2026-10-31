use anyhow::{ensure, Result};
use mongodb::bson::{doc, DateTime};
use porthub_api::{config::Config, terminal_grants as grants, App};
use porthub_terminal::protocol::*;
mod support;
use support::Case;
fn api<T>(value: porthub_api::error::ApiResult<T>) -> Result<T> {
    value.map_err(|e| anyhow::anyhow!("{}", e.detail))
}

#[tokio::test]
#[ignore = "requires isolated MongoDB"]
async fn recovery_preserves_role_across_api_restart_and_revocation_fences_old_sockets() -> Result<()>
{
    let case = Case::new(Config::default()).await?;
    api(grants::ensure_indexes(&case.app).await)?;
    let id = random_token(16);
    case.app
        .collection("terminal_sessions")
        .insert_one(doc! {"_id":&id,"state":"active"})
        .await?;
    let (initial, raw) = api(grants::create(&case.app, &id, true, 60).await)?;
    let stored = case
        .app
        .collection("terminal_grants")
        .find_one(doc! {"_id":digest(&raw)})
        .await?
        .unwrap();
    ensure!(
        !format!("{stored:?}").contains(&raw),
        "raw recovery credential must not be persisted"
    );
    ensure!(stored.get_bool("read_only")?);
    let restarted = App::new(Config::default(), case.db.clone());
    let resumed = api(grants::resume(&restarted, &raw).await)?;
    ensure!(
        resumed.identity == initial.identity && resumed.read_only && resumed.lease != initial.lease
    );
    ensure!(
        grants::renew(&case.app, &initial).await.is_err(),
        "superseded socket lease must be fenced"
    );
    let before = case
        .app
        .collection("terminal_grants")
        .find_one(doc! {"_id":digest(&raw)})
        .await?
        .unwrap()
        .get_datetime("valid_until")?
        .to_owned();
    api(grants::release(&case.app, &initial).await)?;
    let after = case
        .app
        .collection("terminal_grants")
        .find_one(doc! {"_id":digest(&raw)})
        .await?
        .unwrap()
        .get_datetime("valid_until")?
        .to_owned();
    ensure!(
        before == after,
        "stale socket cannot shorten replacement lease"
    );
    let other = random_token(16);
    api(grants::revoke(&case.app, &other, resumed.identity).await)?;
    api(grants::renew(&case.app, &resumed).await)?;
    api(grants::revoke(&case.app, &id, resumed.identity).await)?;
    ensure!(grants::resume(&restarted, &raw).await.is_err());
    ensure!(grants::renew(&case.app, &resumed).await.is_err());
    let (writer, writer_raw) = api(grants::create(&case.app, &id, false, 60).await)?;
    ensure!(!api(grants::resume(&restarted, &writer_raw).await)?.read_only);
    api(grants::end(&case.app, &id).await)?;
    ensure!(grants::resume(&case.app, &writer_raw).await.is_err());
    ensure!(grants::renew(&case.app, &writer).await.is_err());
    let (_, expired) = api(grants::create(&case.app, &id, true, 60).await)?;
    case.app
        .collection("terminal_grants")
        .update_one(
            doc! {"_id":digest(&expired)},
            doc! {"$set":{"valid_until":DateTime::from_millis(1)}},
        )
        .await?;
    ensure!(
        grants::resume(&case.app, &expired).await.is_err(),
        "expiry must not depend on TTL sweep"
    );
    let (_, ended) = api(grants::create(&case.app, &id, true, 60).await)?;
    case.app
        .collection("terminal_sessions")
        .update_one(doc! {"_id":&id}, doc! {"$set":{"state":"ended"}})
        .await?;
    ensure!(grants::resume(&case.app, &ended).await.is_err());
    ensure!(grants::create(&case.app, &id, true, 60).await.is_err());
    ensure!(grants::resume(&case.app, "invalid").await.is_err());
    case.db.drop().await?;
    Ok(())
}
