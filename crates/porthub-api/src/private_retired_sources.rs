//! Always-on denial-only retained source catalog. This module does not create
//! reservations or authorize migrations, packets, routes or credentials. Legacy
//! builds must honor completed old-source denials even without the experimental
//! migration/transport implementation.
use crate::{App,error::{ApiError,ApiResult},domain::enrollment::Network};
use mongodb::bson::{doc,Document};
use futures_util::TryStreamExt;
use std::{collections::HashMap,net::Ipv4Addr};
fn invalid()->ApiError{ApiError::new(axum::http::StatusCode::CONFLICT,"Invalid retained private source reservation; refusing address reuse")}
pub(crate) async fn occupied(app:&App)->ApiResult<(Vec<Network>,Vec<Ipv4Addr>)>{
    let mut cursor=app.collection("private_retired_sources").find(doc!{}).projection(doc!{"_id":1,"workspace":1,"previous_generation":1,"activated":1,"cidrs":1,"addresses":1}).batch_size(32).await?;
    let mut heads:HashMap<String,Option<Document>>=HashMap::new();let mut pools=Vec::new();let mut addresses=Vec::new();
    while let Some(row)=cursor.try_next().await?{
        let workspace=row.get_str("workspace").map_err(|_|invalid())?;
        let job=row.get_str("_id").map_err(|_|invalid())?;
        let previous=row.get_i64("previous_generation").map_err(|_|invalid())?;
        if previous<0||mongodb::bson::oid::ObjectId::parse_str(workspace).is_err()||job.len()!=32||!job.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){return Err(invalid());}
        if row.contains_key("activated")&&row.get_bool("activated").is_err(){return Err(invalid());}
        let active=if row.get_bool("activated")==Ok(true){true}else{
            if !heads.contains_key(workspace){heads.insert(workspace.into(),app.collection("private_renumber_heads").find_one(doc!{"_id":workspace}).projection(doc!{"generation":1,"job":1,"state":1}).await?);}
            heads[workspace].as_ref().is_some_and(|h|h.get_i64("generation").is_ok_and(|g|g>previous)||(h.get_str("job").ok()==Some(job)&&h.get_str("state").ok()!=Some("stable")))
        };
        if !active{continue;}
        let cidrs=row.get_array("cidrs").map_err(|_|invalid())?;let old=row.get_array("addresses").map_err(|_|invalid())?;
        if cidrs.is_empty()||cidrs.len()>32||old.is_empty()||old.len()>65536{return Err(invalid());}
        for pool in cidrs{pools.push(Network::parse(pool.as_str().ok_or_else(invalid)?).map_err(|_|invalid())?);}
        for address in old{let ip:Ipv4Addr=address.as_str().ok_or_else(invalid)?.parse().map_err(|_|invalid())?;if !ip.is_private(){return Err(invalid());}addresses.push(ip);}
    }Ok((pools,addresses))
}

#[cfg(all(test,not(feature="private-sparse")))]mod tests{
    use super::*;
    use futures_util::FutureExt;
    use mongodb::bson::oid::ObjectId;
    #[tokio::test]
    #[ignore="requires fresh Root-owned isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
    async fn actual_default_build_honors_completed_retention_without_breaking_normal_legacy_allocation()->anyhow::Result<()>{
        let client=mongodb::Client::with_uri_str(std::env::var("PORTHUB_TEST_MONGO_URI")?).await?;let db=client.database(&format!("porthub_retained_default_{}",uuid::Uuid::new_v4().simple()));
        let result=std::panic::AssertUnwindSafe(async{
            let app=App::new(crate::config::Config::default(),db.clone());let owner=ObjectId::new().to_hex();let other=ObjectId::new().to_hex();
            assert!(occupied(&app).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?.0.is_empty());
            let reservation=doc!{"_id":"a".repeat(32),"workspace":&owner,"previous_generation":0_i64,"activated":true,"cidrs":["10.203.0.0/24"],"addresses":["10.203.0.2"]};
            app.collection("private_retired_sources").insert_one(reservation.clone()).await?;
            app.collection("private_renumber_heads").insert_one(doc!{"_id":&owner,"state":"stable","generation":1_i64}).await?;
            assert!(crate::domain::private_networks::save(&app,&other,Network::parse("10.203.0.0/24").unwrap(),"other.private").await.is_err());
            crate::domain::private_networks::save(&app,&other,Network::parse("10.204.0.0/24").unwrap(),"other.private").await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            app.collection("private_renumber_heads").delete_one(doc!{"_id":&owner}).await?;
            let restarted=App::new(crate::config::Config::default(),db.clone());
            assert!(crate::domain::private_networks::save(&restarted,&other,Network::parse("10.203.0.0/24").unwrap(),"other.private").await.is_err());
            assert_eq!(restarted.collection("private_retired_sources").find_one(doc!{"_id":reservation.get("_id")}).await?.unwrap(),reservation);
            assert_eq!(restarted.collection("private_networks").find_one(doc!{"_id":&other}).await?.unwrap().get_str("cidr")?,"10.204.0.0/24");
            Ok::<_,anyhow::Error>(())
        }).catch_unwind().await;db.drop().await?;match result{Ok(value)=>value,Err(panic)=>std::panic::resume_unwind(panic)}
    }
    #[tokio::test]
    #[ignore="requires fresh Root-owned isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
    async fn actual_default_reader_ignores_inert_orphan_but_honors_uncertain_head_activation()->anyhow::Result<()>{
        let client=mongodb::Client::with_uri_str(std::env::var("PORTHUB_TEST_MONGO_URI")?).await?;let db=client.database(&format!("porthub_retained_orphan_{}",uuid::Uuid::new_v4().simple()));
        let result=std::panic::AssertUnwindSafe(async{
            let app=App::new(crate::config::Config::default(),db.clone());let owner=ObjectId::new().to_hex();let job="b".repeat(32);
            let orphan=doc!{"_id":&job,"workspace":&owner,"previous_generation":0_i64,"cidrs":["10.203.0.0/24"],"addresses":["10.203.0.2"]};app.collection("private_retired_sources").insert_one(orphan.clone()).await?;
            assert!(occupied(&app).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?.0.is_empty());
            app.collection("private_renumber_heads").insert_one(doc!{"_id":&owner,"state":"stable","generation":0_i64}).await?;
            assert!(occupied(&app).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?.0.is_empty());
            app.collection("private_renumber_heads").update_one(doc!{"_id":&owner},doc!{"$set":{"state":"applying","generation":1_i64,"job":&job}}).await?;
            let reopened=App::new(crate::config::Config::default(),db.clone());assert!(occupied(&reopened).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?.1.contains(&"10.203.0.2".parse()?));
            assert_eq!(reopened.collection("private_retired_sources").find_one(doc!{"_id":&job}).await?.unwrap(),orphan);
            Ok::<_,anyhow::Error>(())
        }).catch_unwind().await;db.drop().await?;match result{Ok(value)=>value,Err(panic)=>std::panic::resume_unwind(panic)}
    }
}
