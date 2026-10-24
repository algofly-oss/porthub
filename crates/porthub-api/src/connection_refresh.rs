//! Refresh leases survive process interruption. A concurrent user edit removes
//! its lease, preventing the worker from re-enabling a deliberately disabled port.
use crate::{error::ApiResult, firewall, generated, routes::connections, store, App};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, Bson, DateTime, Document};
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;
fn minutes(record: &Document) -> i64 {
    match record.get("auto_refresh_interval_minutes") {
        Some(Bson::Int32(n)) => *n as i64,
        Some(Bson::Int64(n)) => *n,
        _ => 60,
    }
    .clamp(1, 10080)
}
async fn wake(app: &App, record: &Document) {
    app.notify_config(&store::id(record.get("machine_id")))
        .await;
}
async fn retry(app: &App, record: &Document) -> ApiResult<()> {
    let next = if record.get_bool("auto_refresh_enabled") == Ok(true) {
        Bson::DateTime(DateTime::from_millis(
            DateTime::now().timestamp_millis() + 60_000,
        ))
    } else {
        Bson::Null
    };
    app.collection("connections")
        .update_one(
            doc! {"_id":record.get("_id")},
            doc! {"$set":{"auto_refresh_next_at":next}},
        )
        .await?;
    Ok(())
}
pub async fn finish(app: &App, record: &Document) -> ApiResult<Option<Document>> {
    let _guard = app.connection_lock.lock().await;
    let Some(latest) = app
        .collection("connections")
        .find_one(doc! {"_id":record.get("_id")})
        .await?
    else {
        return Ok(None);
    };
    let lease = record
        .get_document("native_refresh")
        .ok()
        .and_then(|lease| lease.get_str("id").ok());
    if lease.is_none()
        || latest
            .get_document("native_refresh")
            .ok()
            .and_then(|lease| lease.get_str("id").ok())
            != lease
    {
        return Ok(Some(latest));
    }
    let now = DateTime::now();
    let mut candidate = latest.clone();
    candidate.remove("native_refresh");
    candidate.insert("enabled", true);
    candidate.insert("updated_at", now);
    candidate.insert("auto_refreshed_at", now);
    let next = if candidate.get_bool("auto_refresh_enabled") == Ok(true) {
        Bson::DateTime(DateTime::from_millis(
            now.timestamp_millis() + minutes(&candidate) * 60_000,
        ))
    } else {
        Bson::Null
    };
    candidate.insert("auto_refresh_next_at", next);
    app.collection("connections")
        .replace_one(
            doc! {"_id":latest.get("_id"),"native_refresh.id":lease},
            candidate.clone(),
        )
        .await?;
    if let Err(error) = async {
        firewall::sync(app, &candidate).await?;
        generated::rebuild(app).await
    }
    .await
    {
        connections::restore(app, Some(&latest), &candidate).await;
        return Err(error);
    }
    wake(app, &candidate).await;
    Ok(Some(candidate))
}
pub async fn refresh(
    app: &App,
    record: Document,
    delay: Duration,
    mut stop: Option<watch::Receiver<bool>>,
) -> ApiResult<Option<Document>> {
    let disabled = {
        let _guard = app.connection_lock.lock().await;
        let Some(latest)=app.collection("connections").find_one(doc! {"_id":record.get("_id"),"enabled":{"$ne":false},"native_refresh":{"$exists":false}}).await?else{return Ok(None)};
        let machine = connections::machine(app, &latest).await?;
        if machine.is_none_or(|m| {
            m.get_bool("enabled") == Ok(false) || m.get_bool("deletion_pending") == Ok(true)
        }) {
            retry(app, &latest).await?;
            return Ok(None);
        }
        let mut candidate = latest.clone();
        candidate.insert("enabled", false);
        candidate.insert("updated_at", DateTime::now());
        candidate.insert(
            "native_refresh",
            doc! {"id":uuid::Uuid::new_v4().to_string(),"started_at":DateTime::now()},
        );
        app.collection("connections")
            .replace_one(doc! {"_id":latest.get("_id")}, candidate.clone())
            .await?;
        if let Err(error) = async {
            generated::rebuild(app).await?;
            firewall::sync(app, &candidate).await
        }
        .await
        {
            connections::restore(app, Some(&latest), &candidate).await;
            retry(app, &latest).await?;
            return Err(error);
        }
        wake(app, &candidate).await;
        candidate
    };
    if let Some(stop) = &mut stop {
        tokio::select! {_=tokio::time::sleep(delay)=>{},_=stop.changed()=>{}}
    } else {
        tokio::time::sleep(delay).await;
    }
    finish(app, &disabled).await
}
pub async fn recover(app: &App, all: bool) -> ApiResult<()> {
    let mut filter = doc! {"native_refresh.id":{"$exists":true}};
    if !all {
        filter.insert(
            "native_refresh.started_at",
            doc! {"$lt":DateTime::from_millis(DateTime::now().timestamp_millis()-30_000)},
        );
    }
    let leases: Vec<Document> = app
        .collection("connections")
        .find(filter)
        .limit(25)
        .await?
        .try_collect()
        .await?;
    for record in leases {
        finish(app, &record).await?;
    }
    Ok(())
}
pub async fn run(app: Arc<App>, mut stop: watch::Receiver<bool>) {
    let mut first = true;
    loop {
        if *stop.borrow() {
            return;
        }
        let work=async {
            recover(&app,first).await?;first=false;
            let due:Vec<Document>=app.collection("connections").find(doc! {"enabled":{"$ne":false},"auto_refresh_enabled":true,"auto_refresh_interval_minutes":{"$gte":1},
                "$or":[{"auto_refresh_next_at":{"$lte":DateTime::now()}},{"auto_refresh_next_at":Bson::Null}]}).limit(25).await?.try_collect().await?;
            for record in due {if *stop.borrow(){break;}refresh(&app,record,Duration::from_secs(5),Some(stop.clone())).await?;}
            Ok::<(),crate::error::ApiError>(())
        }.await;
        if let Err(error) = work {
            tracing::warn!(detail=%error.detail,"connection refresh worker will retry");
        }
        tokio::select! {_=tokio::time::sleep(Duration::from_secs(30))=>{},_=stop.changed()=>return}
    }
}
