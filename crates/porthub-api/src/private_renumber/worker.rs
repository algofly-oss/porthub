//! One experimental recovery worker; never creates or automatically authorizes
//! migrations. Dropping an in-flight phase leaves an exact durable fenced job.
use crate::App;
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;
pub async fn run(app: Arc<App>, mut stop: watch::Receiver<bool>) {
    let mut migrations = None;
    let mut enrollments = None;
    let mut native_repairs=None;
    loop {
        if *stop.borrow() {
            break;
        }
        let pass = async {
            let repairs=super::native_repair::pending_once(&app,native_repairs.clone()).await;
            let recovery = super::recover::pending_once(&app, migrations).await;
            let deferred = super::deferred::pending_once(&app, enrollments).await;
            (repairs,recovery, deferred)
        };
        tokio::select! {
            biased;
            changed=stop.changed()=>{if changed.is_err()||*stop.borrow(){break;}},
            (repairs,recovery,deferred)=pass=>{
                match repairs{Ok(next)=>native_repairs=next,Err(_)=>tracing::warn!("Native collision repair remains queued; source stays quarantined")}
                match recovery {Ok(batch)=>migrations=batch.next,Err(_)=>tracing::warn!("Private address recovery remains fenced; retrying bounded discovery")}
                match deferred {Ok(batch)=>enrollments=batch.next,Err(_)=>tracing::warn!("Deferred private enrollment remains queued; retrying bounded discovery")}
            }
        }
        tokio::select! {
            biased;
            changed=stop.changed()=>{if changed.is_err()||*stop.borrow(){break;}},
            _=tokio::time::sleep(Duration::from_secs(5))=>{},
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use mongodb::bson::{doc, oid::ObjectId};
    #[tokio::test]
    #[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
    async fn shutdown_during_real_drain_releases_guards_and_keeps_durable_job_fenced(
    ) -> anyhow::Result<()> {
        let client =
            mongodb::Client::with_uri_str(std::env::var("PORTHUB_TEST_MONGO_URI")?).await?;
        let db = client.database(&format!(
            "porthub_renumber_stop_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let result=async {
            let app=Arc::new(App::new(crate::config::Config::default(),db.clone()));let owner=ObjectId::new();let machine=ObjectId::new();let job="4123456789abcdef0123456789abcdef";
            let row=super::super::recovery::Assignment{peer:format!("{owner}:{machine}"),machine:machine.to_hex(),workspace:owner.to_hex(),credential_generation:"enrollment-1".into(),old:"10.203.0.2".parse()?,new:"10.204.0.2".parse()?,previous_generation:0,generation:1};
            let peer=doc!{"_id":&row.peer,"workspace_id":owner,"machine_id":machine,"ip":row.old.to_string(),"enrollment_generation":"enrollment-1","credential_hash":"unchanged-fixture-hash","enabled":true};
            app.collection("private_peers").insert_one(peer.clone()).await?;
            let guard=super::super::fence::exclusive(&app,owner).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            super::super::journal::prepare(&guard,job,&[row],&["10.204.0.0/16".into()]).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;drop(guard);
            let (stopping,stop)=watch::channel(false);let worker=tokio::spawn(run(app.clone(),stop));
            tokio::time::timeout(Duration::from_secs(2),async{while !app.private_sparse.workspace_fences.held(&owner.to_hex()).await {tokio::task::yield_now().await;}}).await?;
            stopping.send(true)?;tokio::time::timeout(Duration::from_secs(2),worker).await??;
            assert!(app.private_network_lock.try_lock().is_ok());
            assert!(super::super::fence::revocation(&app,owner).await.is_ok());
            assert!(super::super::fence::stable(&app,owner).await.is_err());
            assert_eq!(app.collection("private_peers").find_one(doc!{"_id":peer.get("_id")}).await?.unwrap(),peer);
            assert_eq!(app.collection("private_renumber_heads").find_one(doc!{"_id":owner.to_hex()}).await?.unwrap().get_str("state")?,"applying");
            Ok::<_,anyhow::Error>(())
        }.await;
        db.drop().await?;
        result
    }
}
