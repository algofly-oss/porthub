//! Durable one-row-per-machine automatic-enrollment deferral during migration.
//! No credential, token, name, rule, or device setting is copied into this queue.
use super::journal;
use crate::{
    error::{ApiError, ApiResult},
    App,
};
use axum::http::StatusCode;
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, Document};
pub(crate) async fn record(app: &App, machine: &Document, owner: ObjectId) -> ApiResult<()> {
    let id = machine
        .get_object_id("_id")
        .map_err(|_| ApiError::bad_request("Invalid deferred machine identity"))?;
    journal::durable(app, "private_renumber_deferred")
        .update_one(
            doc! {"_id":id.to_hex()},
            doc! {"$set":{"workspace":owner,"nonce":uuid::Uuid::new_v4().simple().to_string()}},
        )
        .upsert(true)
        .await?;
    Ok(())
}
pub struct Batch {
    pub attempted: usize,
    pub completed: usize,
    pub next: Option<ObjectId>,
}
/// Fresh machine/owner/revocation reads precede the existing enrollment path.
/// Deletion is bound to the observed nonce, so a replacement queue row survives.
pub async fn pending_once(app: &App, after: Option<ObjectId>) -> ApiResult<Batch> {
    let queue = journal::durable(app, "private_renumber_deferred");
    let filter = after
        .map(|id| doc! {"_id":{"$gt":id.to_hex()}})
        .unwrap_or_default();
    let rows: Vec<_> = queue
        .find(filter)
        .sort(doc! {"_id":1})
        .limit(16)
        .await?
        .try_collect()
        .await?;
    let mut result = Batch {
        attempted: 0,
        completed: 0,
        next: None,
    };
    for row in rows {
        let id = ObjectId::parse_str(
            row.get_str("_id")
                .map_err(|_| ApiError::bad_request("Invalid deferred identity"))?,
        )
        .map_err(|_| ApiError::bad_request("Invalid deferred identity"))?;
        let owner = row
            .get_object_id("workspace")
            .map_err(|_| ApiError::bad_request("Invalid deferred workspace"))?;
        let nonce = row
            .get_str("nonce")
            .ok()
            .filter(|s| s.len() == 32)
            .ok_or_else(|| {
                ApiError::new(StatusCode::CONFLICT, "Invalid deferred enrollment record")
            })?;
        result.next = Some(id);
        result.attempted += 1;
        let machine=app.collection("machines").find_one(doc!{"_id":id,"user_id":owner,"private_owner_revoked":{"$ne":true},"deletion_pending":{"$ne":true},"native_deletion":{"$exists":false}}).await?;
        let completed = if let Some(machine) = machine {
            if crate::domain::enrollment::ensure(app, &machine)
                .await
                .is_err()
            {
                false
            } else {
                app.collection("private_peers")
                    .find_one(doc! {"machine_id":id,"owner_id":owner})
                    .projection(doc! {"_id":1})
                    .await?
                    .is_some()
            }
        } else {
            true
        };
        if completed {
            let removed = queue
                .delete_one(doc! {"_id":id.to_hex(),"workspace":owner,"nonce":nonce})
                .await?;
            result.completed += removed.deleted_count as usize;
        }
    }
    Ok(result)
}
