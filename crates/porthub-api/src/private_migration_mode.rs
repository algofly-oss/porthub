//! Read-only startup guard against accidentally dropping an active experimental
//! migration fence by changing this binary's feature mode.
use crate::{
    error::{ApiError, ApiResult},
    App,
};
use axum::http::StatusCode;
use mongodb::bson::doc;
pub async fn startup_check(app: &App) -> ApiResult<()> {
    verify(app, cfg!(feature = "private-sparse")).await
}
async fn verify(app: &App, recovery_enabled: bool) -> ApiResult<()> {
    if !recovery_enabled
        && app
            .collection("private_renumber_heads")
            .find_one(doc! {"state":{"$ne":"stable"}})
            .projection(doc! {"_id":1})
            .await?
            .is_some()
    {
        return Err(ApiError::new(StatusCode::CONFLICT,"Pending private address migration requires a private-sparse recovery build; refusing legacy startup"));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
    async fn legacy_startup_cannot_bypass_pending_or_unknown_migration_phase() -> anyhow::Result<()>
    {
        let client =
            mongodb::Client::with_uri_str(std::env::var("PORTHUB_TEST_MONGO_URI")?).await?;
        let db = client.database(&format!(
            "porthub_renumber_mode_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let result = async {
            let app = App::new(crate::config::Config::default(), db.clone());
            assert!(verify(&app, false).await.is_ok());
            let id = mongodb::bson::oid::ObjectId::new().to_hex();
            for state in ["applying", "committing", "preparing", "unrecognized"] {
                app.collection("private_renumber_heads")
                    .update_one(
                        doc! {"_id":&id},
                        doc! {"$set":{"state":state,"generation":1_i64}},
                    )
                    .upsert(true)
                    .await?;
                let before = app
                    .collection("private_renumber_heads")
                    .find_one(doc! {"_id":&id})
                    .await?
                    .unwrap();
                assert!(
                    verify(&app, false).await.is_err(),
                    "legacy mode ignored {state}"
                );
                assert!(verify(&app, true).await.is_ok());
                assert_eq!(
                    before,
                    app.collection("private_renumber_heads")
                        .find_one(doc! {"_id":&id})
                        .await?
                        .unwrap(),
                    "mode check mutated a journal"
                );
            }
            app.collection("private_renumber_heads")
                .update_one(doc! {"_id":&id}, doc! {"$set":{"state":"stable"}})
                .await?;
            assert!(verify(&app, false).await.is_ok());
            Ok::<_, anyhow::Error>(())
        }
        .await;
        db.drop().await?;
        result
    }
}
