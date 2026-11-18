//! Bounded, restart-safe dispatch of already authorized complete migration heads.
//! Does not create a migration, choose pools, or expose a public endpoint.
use super::{apply, finish, journal};
use crate::{
    error::{ApiError, ApiResult},
    App,
};
use axum::http::StatusCode;
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId};
const BATCH: i64 = 8;
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Committed,
    Idle,
    Fenced,
}
#[derive(Debug)]
pub struct Attempt {
    pub workspace: ObjectId,
    pub outcome: Outcome,
}
pub struct Batch {
    pub attempts: Vec<Attempt>,
    pub next: Option<ObjectId>,
}
fn conflict(s: &str) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, s)
}
pub async fn workspace(app: &App, owner: ObjectId) -> ApiResult<Outcome> {
    journal::indexes(app).await?;
    let head = app
        .collection("private_renumber_heads")
        .find_one(doc! {"_id":owner.to_hex()})
        .await?;
    let Some(head) = head else {
        return Ok(Outcome::Idle);
    };
    if head.get_str("state").ok() == Some("stable") {
        return Ok(Outcome::Idle);
    }
    let job = head
        .get_str("job")
        .ok()
        .filter(|s| {
            s.len() == 32
                && s.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
        .ok_or_else(|| conflict("Invalid owned migration job"))?;
    if head.get_i64("plan_version").ok() != Some(2) {
        return Err(conflict(
            "Unsupported prototype migration requires explicit recovery",
        ));
    }
    match head.get_str("state").ok() {
        Some("applying") => {
            let mut guard = apply::run_retained(app, owner, job, apply::Fault::None).await?;
            guard.reacquire_allocation().await;
            finish::run_guarded(&guard, job, finish::Fault::None).await?;
        }
        Some("committing") => {
            finish::run(app, owner, job, finish::Fault::None).await?;
        }
        _ => {
            return Err(conflict(
                "Invalid migration phase; workspace remains fenced",
            ))
        }
    }
    Ok(Outcome::Committed)
}
/// Keyset cursor advances even past a failed workspace, so one permanently
/// fenced journal does not monopolize discovery. State/index query returns at
/// most8 headers; names, credentials and assignment data are never in reports.
pub async fn pending_once(app: &App, after: Option<ObjectId>) -> ApiResult<Batch> {
    journal::indexes(app).await?;
    let mut query = doc! {"state":{"$in":["applying","committing","preparing"]}};
    if let Some(after) = after {
        query.insert("_id", doc! {"$gt":after.to_hex()});
    }
    let heads: Vec<_> = app
        .collection("private_renumber_heads")
        .find(query)
        .projection(doc! {"_id":1})
        .sort(doc! {"_id":1})
        .limit(BATCH)
        .await?
        .try_collect()
        .await?;
    let mut attempts = Vec::new();
    let mut next = None;
    for head in heads {
        let owner = ObjectId::parse_str(
            head.get_str("_id")
                .map_err(|_| conflict("Invalid migration workspace identity"))?,
        )
        .map_err(|_| conflict("Invalid migration workspace identity"))?;
        next = Some(owner);
        let outcome = workspace(app, owner).await.unwrap_or(Outcome::Fenced);
        attempts.push(Attempt {
            workspace: owner,
            outcome,
        });
    }
    Ok(Batch { attempts, next })
}
