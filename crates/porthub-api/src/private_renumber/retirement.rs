//! Old addresses/ranges are NOT reusable on a nominal lease timer. Retention is
//! denial-only and survives process restart and completion of the migration.
use crate::{App,error::{ApiError,ApiResult},domain::enrollment::Network};
use mongodb::bson::{doc,oid::ObjectId,Document};
use super::{journal,recovery::Assignment};
use std::net::Ipv4Addr;
fn invalid()->ApiError{ApiError::new(axum::http::StatusCode::CONFLICT,"Invalid retained private source reservation; recovery required")}
pub(super) async fn stage(app:&App,job:&str,rows:&[Assignment],previous:Option<&Document>)->ApiResult<()>{
    let first=rows.first().ok_or_else(invalid)?;
    let pools=crate::domain::private_networks::pools(&previous.cloned().unwrap_or_default())?.into_iter().map(|p|p.cidr()).collect::<Vec<_>>();
    let old=rows.iter().map(|r|r.old.to_string()).collect::<Vec<_>>();
    let immutable=doc!{"_id":job,"workspace":&first.workspace,"previous_generation":first.previous_generation as i64,"cidrs":pools,"addresses":old};
    if mongodb::bson::to_vec(&immutable).map_err(|_|invalid())?.len()>4*1024*1024{return Err(invalid());}
    let collection=journal::durable(app,"private_retired_sources");
    if collection.find_one(doc!{"_id":job}).await?.is_none()&&collection.count_documents(doc!{"workspace":&first.workspace}).limit(1025).await?>=1024{return Err(ApiError::new(axum::http::StatusCode::CONFLICT,"Retained private source history requires operator review; no address was recycled"));}
    collection.update_one(doc!{"_id":job},doc!{"$setOnInsert":&immutable}).upsert(true).await?;
    let mut readback=collection.find_one(doc!{"_id":job}).await?.ok_or_else(invalid)?;readback.remove("activated");
    if readback!=immutable{return Err(invalid());}Ok(())
}
pub(super) async fn activate(app:&App,owner:ObjectId,job:&str)->ApiResult<()>{
    let result=journal::durable(app,"private_retired_sources").update_one(doc!{"_id":job,"workspace":owner.to_hex()},doc!{"$set":{"activated":true}}).await?;
    if result.matched_count!=1{return Err(invalid());}Ok(())
}
/// Prepared orphan rows confer no reservation. A head activation is sufficient
/// even if the following acknowledgement/activated write was lost in a crash.
pub(crate) async fn occupied(app:&App)->ApiResult<(Vec<Network>,Vec<Ipv4Addr>)>{crate::private_retired_sources::occupied(app).await}
