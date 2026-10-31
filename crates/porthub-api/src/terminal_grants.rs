//! Browser recovery capabilities are independent of join invitations. Only
//! hashes are stored. A short renewable lease bounds abandoned credentials;
//! active sockets renew it, so invitation expiry never interrupts a guest.
use crate::{
    error::{ApiError, ApiResult},
    store, App,
};
use mongodb::{
    bson::{doc, DateTime},
    options::IndexOptions,
    IndexModel,
};
use porthub_terminal::protocol::{digest, participant_id, random_token, token};
use std::time::Duration;

#[derive(Clone)]
pub struct Grant {
    pub hash: String,
    pub session: String,
    pub identity: u64,
    pub read_only: bool,
    pub lease: String,
    pub grace: u32,
}
fn unavailable() -> ApiError {
    ApiError::bad_request("terminal recovery credential expired or revoked")
}
fn deadline(seconds: u32) -> DateTime {
    DateTime::from_millis(DateTime::now().timestamp_millis() + i64::from(seconds) * 1000)
}
impl Grant {
    fn filter(&self) -> mongodb::bson::Document {
        doc! {"_id":&self.hash,"session_id":&self.session,"lease":&self.lease,"active":true,"valid_until":{"$gt":DateTime::now()}}
    }
}
pub async fn ensure_indexes(app: &App) -> ApiResult<()> {
    let collection = app.collection("terminal_grants");
    collection
        .create_index(
            IndexModel::builder()
                .keys(doc! {"valid_until":1})
                .options(IndexOptions::builder().expire_after(Duration::ZERO).build())
                .build(),
        )
        .await?;
    collection
        .create_index(
            IndexModel::builder()
                .keys(doc! {"session_id":1,"identity":1})
                .options(IndexOptions::builder().unique(true).build())
                .build(),
        )
        .await?;
    Ok(())
}
pub async fn create(
    app: &App,
    session: &str,
    read_only: bool,
    grace: u32,
) -> ApiResult<(Grant, String)> {
    if !(10..=300).contains(&grace) || !token(session, 32) {
        return Err(unavailable());
    }
    if app
        .collection("terminal_sessions")
        .find_one(doc! {"_id":session,"state":"active"})
        .await?
        .is_none()
    {
        return Err(unavailable());
    }
    // Expires are enforced in the query, independently of Mongo's delayed TTL sweep.
    if app
        .collection("terminal_grants")
        .count_documents(
            doc! {"session_id":session,"active":true,"valid_until":{"$gt":DateTime::now()}},
        )
        .await?
        >= 128
    {
        return Err(ApiError::bad_request(
            "terminal recovery capacity reached; retry shortly",
        ));
    }
    let raw = random_token(32);
    let grant = Grant {
        hash: digest(&raw),
        session: session.into(),
        identity: participant_id(),
        read_only,
        lease: random_token(16),
        grace,
    };
    app.collection("terminal_grants").insert_one(doc!{"_id":&grant.hash,"session_id":session,"identity":grant.identity as i64,"read_only":read_only,"lease":&grant.lease,"grace":grace as i64,"active":true,"valid_until":deadline(grace+30)}).await?;
    Ok((grant, raw))
}
pub async fn resume(app: &App, raw: &str) -> ApiResult<Grant> {
    if !token(raw, 64) {
        return Err(unavailable());
    }
    let hash = digest(raw);
    let previous = app
        .collection("terminal_grants")
        .find_one(doc! {"_id":&hash,"active":true,"valid_until":{"$gt":DateTime::now()}})
        .await?
        .ok_or_else(unavailable)?;
    let session = store::string(&previous, "session_id").to_owned();
    let identity = previous.get_i64("identity").map_err(|_| unavailable())?;
    let grace = previous.get_i64("grace").map_err(|_| unavailable())?;
    if !token(&session, 32)
        || !(1..(1i64 << 53)).contains(&identity)
        || !(10..=300).contains(&grace)
    {
        return Err(unavailable());
    }
    if app
        .collection("terminal_sessions")
        .find_one(doc! {"_id":&session,"state":"active"})
        .await?
        .is_none()
    {
        return Err(unavailable());
    }
    let old_lease = store::string(&previous, "lease");
    if !token(old_lease, 32) {
        return Err(unavailable());
    }
    let grant = Grant {
        hash,
        session,
        identity: identity as u64,
        read_only: previous.get_bool("read_only").map_err(|_| unavailable())?,
        lease: random_token(16),
        grace: grace as u32,
    };
    let result=app.collection("terminal_grants").update_one(doc!{"_id":&grant.hash,"active":true,"lease":old_lease,"valid_until":{"$gt":DateTime::now()}},doc!{"$set":{"lease":&grant.lease,"valid_until":deadline(grant.grace+30)}}).await?;
    if result.matched_count != 1 {
        return Err(unavailable());
    }
    Ok(grant)
}
pub async fn renew(app: &App, grant: &Grant) -> ApiResult<()> {
    let result = app
        .collection("terminal_grants")
        .update_one(
            grant.filter(),
            doc! {"$set":{"valid_until":deadline(grant.grace+30)}},
        )
        .await?;
    if result.matched_count != 1 {
        return Err(unavailable());
    }
    Ok(())
}
pub async fn release(app: &App, grant: &Grant) -> ApiResult<()> {
    // A stale socket must never shorten the replacement connection's lease.
    app.collection("terminal_grants")
        .update_one(
            grant.filter(),
            doc! {"$set":{"valid_until":deadline(grant.grace)}},
        )
        .await?;
    Ok(())
}
pub async fn revoke(app: &App, session: &str, identity: u64) -> ApiResult<()> {
    app.collection("terminal_grants")
        .update_one(
            doc! {"session_id":session,"identity":identity as i64},
            doc! {"$set":{"active":false,"valid_until":deadline(300)}},
        )
        .await?;
    Ok(())
}
pub async fn end(app: &App, session: &str) -> ApiResult<()> {
    app.collection("terminal_grants")
        .update_many(
            doc! {"session_id":session},
            doc! {"$set":{"active":false,"valid_until":deadline(300)}},
        )
        .await?;
    Ok(())
}
