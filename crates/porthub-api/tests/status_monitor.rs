use anyhow::{ensure, Result};
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime, Document};
use porthub_api::{
    config::Config,
    domain::inventory,
    status_monitor::{self, Monitor},
};
use serde_json::{json, Value};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
mod support;
use support::Case;
fn error(error: porthub_api::error::ApiError) -> anyhow::Error {
    anyhow::anyhow!("{}", error.detail)
}
fn at(millis: i64) -> DateTime {
    DateTime::from_millis(millis)
}
async fn events(case: &Case, id: ObjectId) -> Result<Vec<Document>> {
    Ok(case
        .app
        .collection("machine_status_events")
        .find(doc! {"machine_id":id})
        .sort(doc! {"changed_at":1})
        .await?
        .try_collect()
        .await?)
}
struct Telegram {
    base: String,
    calls: Arc<Mutex<Vec<Value>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Telegram {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Telegram {
    async fn new() -> Result<Self> {
        let calls = Arc::new(Mutex::new(Vec::<Value>::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let router=Router::new().route("/bottest-token/sendMessage",post(
            |State(calls):State<Arc<Mutex<Vec<Value>>>>, Json(body):Json<Value>| async move {
                let status=if body["chat_id"]=="fail" { StatusCode::BAD_REQUEST } else { StatusCode::OK };
                calls.lock().unwrap().push(body);
                (status,Json(json!({"ok":status==StatusCode::OK})))
            })).with_state(calls.clone());
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        Ok(Self { base, calls, task })
    }
    fn messages(&self) -> Vec<Value> {
        self.calls.lock().unwrap().clone()
    }
}
async fn configured(case: &Case) -> Result<ObjectId> {
    let (owner, _) = case.user("alerts@example.invalid", "user").await?;
    case.app.collection("users").update_one(doc! {"_id":owner},doc! {"$set":{
        "telegram_bot_token":"test-token","telegram_chat_ids":["one"],"telegram_alerts_enabled":true,
        "telegram_digest_enabled":true,"telegram_digest_interval_hours":1}}).await?;
    Ok(owner)
}

#[test]
fn last_seen_formats_never_future_and_unit_boundaries() {
    let now = at(1_800_000_000_000);
    assert_eq!(status_monitor::last_seen(None, now), "never");
    for (age, expected) in [
        (-1000, "just now"),
        (59999, "just now"),
        (60000, "1m ago"),
        (3599999, "59m ago"),
        (3600000, "1h ago"),
        (86400000, "1d ago"),
    ] {
        assert_eq!(
            status_monitor::last_seen(Some(&Bson::DateTime(at(now.timestamp_millis() - age))), now),
            expected
        );
    }
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn history_tracks_ttl_auth_disabled_and_retirement_without_restart_duplicates() -> Result<()>
{
    let case = Case::new(Config {
        machine_online_ttl_millis: 1000,
        ..Config::default()
    })
    .await?;
    let result = async {
        let (owner, cookie) = case.user("history@example.invalid", "user").await?;
        let id = ObjectId::new();
        let now = DateTime::now();
        let t = now.timestamp_millis();
        case.app
            .collection("machines")
            .insert_one(doc! {"_id":id,"user_id":owner,"last_seen_at":now,"auth_required":true})
            .await?;
        let mut monitor = Monitor::default();
        for millis in [t, t + 1000, t + 1001, t + 2000] {
            monitor.tick(&case.app, at(millis)).await.map_err(error)?;
        }
        ensure!(
            events(&case, id)
                .await?
                .iter()
                .map(|e| e.get_str("status").unwrap())
                .collect::<Vec<_>>()
                == ["online", "offline"]
        );
        Monitor::default()
            .tick(&case.app, at(t + 2001))
            .await
            .map_err(error)?;
        ensure!(
            events(&case, id).await?.len() == 2,
            "restart must not duplicate persisted state"
        );
        case.app
            .collection("machines")
            .update_one(doc! {"_id":id}, doc! {"$set":{"last_seen_at":at(t+2100)}})
            .await?;
        monitor.tick(&case.app, at(t + 2100)).await.map_err(error)?;
        case.app
            .collection("machines")
            .update_one(doc! {"_id":id}, doc! {"$set":{"enabled":false}})
            .await?;
        monitor.tick(&case.app, at(t + 2101)).await.map_err(error)?;
        case.app
            .collection("machines")
            .update_one(
                doc! {"_id":id},
                doc! {"$set":{"deletion_pending":true,"enabled":true}},
            )
            .await?;
        monitor.tick(&case.app, at(t + 2102)).await.map_err(error)?;
        ensure!(events(&case, id).await?.len() == 4);
        // History remains available to the owner until retirement is acknowledged.
        let response = case
            .status(
                "GET",
                &format!("/api/machines/{id}/status-history"),
                &cookie,
                Value::Null,
                StatusCode::OK,
            )
            .await?;
        ensure!(response["data"].as_array().unwrap().len() == 4);
        let (_, foreign) = case.user("foreign@example.invalid", "user").await?;
        let response = case
            .status(
                "GET",
                &format!("/api/machines/{id}/status-history"),
                &foreign,
                Value::Null,
                StatusCode::OK,
            )
            .await?;
        ensure!(response["msg"] == "Machine not found");
        Ok::<_, anyhow::Error>(())
    }
    .await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn startup_marks_existing_offline_and_preserves_explicit_flags_and_indexes() -> Result<()> {
    let case = Case::new(Config {
        machine_online_ttl_millis: 1000,
        machine_offline_alert_grace_millis: 1000,
        ..Config::default()
    })
    .await?;
    let result = async {
        let now = at(1_800_000_000_000);
        let owner = ObjectId::new();
        let [old, edge, recent, never, explicit] = [
            ObjectId::new(),
            ObjectId::new(),
            ObjectId::new(),
            ObjectId::new(),
            ObjectId::new(),
        ];
        case.app
            .collection("machines")
            .insert_many([
                doc! {"_id":old,"user_id":owner,"last_seen_at":at(now.timestamp_millis()-2001)},
                doc! {"_id":edge,"last_seen_at":at(now.timestamp_millis()-2000)},
                doc! {"_id":recent,"last_seen_at":at(now.timestamp_millis()-100)},
                doc! {"_id":never},
                doc! {"_id":explicit,"telegram_offline_alerted":false,"last_seen_at":at(0)},
            ])
            .await?;
        status_monitor::initialize(&case.app, now)
            .await
            .map_err(error)?;
        status_monitor::initialize(&case.app, now)
            .await
            .map_err(error)?;
        for id in [edge, recent, never] {
            ensure!(!case
                .app
                .collection("machines")
                .find_one(doc! {"_id":id})
                .await?
                .unwrap()
                .contains_key("telegram_offline_alerted"));
        }
        ensure!(case
            .app
            .collection("machines")
            .find_one(doc! {"_id":old})
            .await?
            .unwrap()
            .get_bool("telegram_offline_alerted")?);
        ensure!(!case
            .app
            .collection("machines")
            .find_one(doc! {"_id":explicit})
            .await?
            .unwrap()
            .get_bool("telegram_offline_alerted")?);
        let indexes: Vec<_> = case
            .app
            .collection("machine_status_events")
            .list_indexes()
            .await?
            .try_collect()
            .await?;
        ensure!(indexes.iter().any(|index| index
            .options
            .as_ref()
            .is_some_and(|opts| opts.expire_after == Some(Duration::from_secs(370 * 86400)))));
        ensure!(indexes
            .iter()
            .any(|index| index.keys == doc! {"machine_id":1,"changed_at":-1}));
        Ok::<_, anyhow::Error>(())
    }
    .await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn instant_alerts_obey_grace_exclusions_recovery_and_stale_heartbeat_guards() -> Result<()> {
    let telegram = Telegram::new().await?;
    let case = Case::new(Config {
        telegram_base_url: telegram.base.clone(),
        machine_online_ttl_millis: 1000,
        machine_offline_alert_grace_millis: 1000,
        ..Config::default()
    })
    .await?;
    let result=async {
        let owner=configured(&case).await?; let id=ObjectId::new();let now=at(1_800_000_000_000);let t=now.timestamp_millis();
        case.app.collection("machines").insert_one(doc! {"_id":id,"user_id":owner,"name":"A <B> & C","last_seen_at":at(t-1001)}).await?;
        status_monitor::alerts_once(&case.app,now).await.map_err(error)?;
        ensure!(telegram.messages().is_empty());
        status_monitor::alerts_once(&case.app,at(t+999)).await.map_err(error)?;
        status_monitor::alerts_once(&case.app,at(t+1000)).await.map_err(error)?;
        ensure!(telegram.messages().len()==1);
        ensure!(telegram.messages()[0]["text"]=="🔴 <b>A &lt;B&gt; &amp; C</b> went offline (last seen just now)");
        let stale=case.app.collection("machines").find_one(doc! {"_id":id}).await?.unwrap();
        case.app.collection("machines").update_one(doc! {"_id":id},doc! {"$set":{"last_seen_at":at(t+1001),"auth_required":true}}).await?;
        status_monitor::process_alert(&case.app,&stale,at(t+1001)).await.map_err(error)?;
        ensure!(telegram.messages().len()==1);
        status_monitor::alerts_once(&case.app,at(t+1001)).await.map_err(error)?;
        ensure!(telegram.messages().len()==2 && telegram.messages()[1]["text"]=="🟢 <b>A &lt;B&gt; &amp; C</b> is back online");
        for field in ["telegram_alerts_excluded","deletion_pending"] {
            case.app.collection("machines").update_one(doc! {"_id":id},doc! {"$set":{field:true,"last_seen_at":at(0)}}).await?;
            status_monitor::alerts_once(&case.app,at(t+1002)).await.map_err(error)?;
            case.app.collection("machines").update_one(doc! {"_id":id},doc! {"$unset":{field:""}}).await?;
        }
        case.app.collection("machines").update_one(doc! {"_id":id},doc! {"$set":{"enabled":false}}).await?;
        status_monitor::alerts_once(&case.app,at(t+1003)).await.map_err(error)?;
        ensure!(telegram.messages().len()==2);
        // A stale offline snapshot must not change flags or alert after a heartbeat.
        let mut stale=stale; stale.insert("telegram_offline_alerted",false);
        case.app.collection("machines").update_one(doc! {"_id":id},doc! {"$set":{"enabled":true,"last_seen_at":at(t+2000),"telegram_offline_alerted":false}}).await?;
        status_monitor::process_alert(&case.app,&stale,at(t+2000)).await.map_err(error)?;
        ensure!(telegram.messages().len()==2);
        ensure!(!case.app.collection("machines").find_one(doc! {"_id":id}).await?.unwrap().get_bool("telegram_offline_alerted")?);
        Ok::<_,anyhow::Error>(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn digest_is_scoped_scheduled_chunked_and_does_not_retry_failed_chats_in_period() -> Result<()>
{
    let telegram = Telegram::new().await?;
    let case = Case::new(Config {
        telegram_base_url: telegram.base.clone(),
        ..Config::default()
    })
    .await?;
    let result = async {
        let owner = configured(&case).await?;
        let other = ObjectId::new();
        let now = at(1_800_000_000_000);
        let t = now.timestamp_millis();
        case.app
            .collection("users")
            .update_one(
                doc! {"_id":owner},
                doc! {"$set":{"telegram_chat_ids":["one","fail"]}},
            )
            .await?;
        case.app
            .collection("machines")
            .insert_many([
                doc! {"user_id":owner,"name":"offline <safe>","last_seen_at":at(t-3600000)},
                doc! {"user_id":owner,"name":"never"},
                doc! {"user_id":owner,"name":"excluded","telegram_alerts_excluded":true},
                doc! {"user_id":owner,"name":"disabled","enabled":false},
                doc! {"user_id":owner,"name":"deleted","deletion_pending":true},
                doc! {"user_id":owner,"name":"online","last_seen_at":now},
                doc! {"user_id":other,"name":"foreign"},
            ])
            .await?;
        status_monitor::digest_once(&case.app, now)
            .await
            .map_err(error)?;
        let messages = telegram.messages();
        ensure!(messages.len() == 2);
        for message in &messages {
            let text = message["text"].as_str().unwrap();
            ensure!(
                text.contains("offline &lt;safe&gt; — last seen 1h ago")
                    && text.contains("never — last seen never")
            );
            for hidden in ["excluded", "disabled", "deleted", "online", "foreign"] {
                ensure!(!text.contains(hidden));
            }
        }
        status_monitor::digest_once(&case.app, at(t + 3599999))
            .await
            .map_err(error)?;
        ensure!(
            telegram.messages().len() == 2,
            "failed chats must not cause repeated sends each scan"
        );
        let long = doc! {"user_id":owner,"name":"<&😀".repeat(85)};
        case.app
            .collection("machines")
            .insert_many((0..12).map(|_| long.clone()))
            .await?;
        status_monitor::digest_once(&case.app, at(t + 3600000))
            .await
            .map_err(error)?;
        ensure!(telegram.messages().len() > 4, "large digests must be split");
        ensure!(telegram.messages().iter().all(|m| m["text"]
            .as_str()
            .unwrap()
            .encode_utf16()
            .count()
            <= 4096));
        case.app
            .collection("users")
            .update_one(
                doc! {"_id":owner},
                doc! {"$set":{"telegram_digest_enabled":false}},
            )
            .await?;
        let count = telegram.messages().len();
        status_monitor::digest_once(&case.app, at(t + 7200000))
            .await
            .map_err(error)?;
        ensure!(telegram.messages().len() == count);
        Ok::<_, anyhow::Error>(())
    }
    .await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn monitor_shutdown_cancels_inflight_notification_and_idle_workers_stop_promptly(
) -> Result<()> {
    let started = Arc::new(tokio::sync::Notify::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let base = format!("http://{}", listener.local_addr()?);
    let notify = started.clone();
    let router = Router::new().fallback(move || {
        let notify = notify.clone();
        async move {
            notify.notify_one();
            std::future::pending::<StatusCode>().await
        }
    });
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    let case = Case::new(Config {
        telegram_base_url: base,
        ..Config::default()
    })
    .await?;
    let result = async {
        let owner = configured(&case).await?;
        case.app
            .collection("machines")
            .insert_one(doc! {"user_id":owner,"last_seen_at":at(0)})
            .await?;
        let (stop, rx) = tokio::sync::watch::channel(false);
        let worker = tokio::spawn(status_monitor::run_alerts(case.app.clone(), rx));
        tokio::time::timeout(Duration::from_secs(3), started.notified()).await?;
        let mut history = Monitor::default();
        tokio::time::timeout(
            Duration::from_secs(1),
            history.tick(&case.app, DateTime::now()),
        )
        .await?
        .map_err(error)?;
        ensure!(
            case.app
                .collection("machine_status_events")
                .count_documents(doc! {})
                .await?
                == 1,
            "stalled Telegram delivery must not stall presence/history"
        );
        stop.send(true)?;
        tokio::time::timeout(Duration::from_secs(1), worker).await??;
        let (_, rx) = tokio::sync::watch::channel(true);
        tokio::time::timeout(
            Duration::from_secs(1),
            status_monitor::run_digest(case.app.clone(), rx),
        )
        .await?;
        let (_, rx) = tokio::sync::watch::channel(true);
        tokio::time::timeout(
            Duration::from_secs(1),
            status_monitor::run(case.app.clone(), rx),
        )
        .await?;
        ensure!(inventory::status_at(&case.app, &doc! {}, DateTime::now()) == "offline");
        Ok::<_, anyhow::Error>(())
    }
    .await;
    server.abort();
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn history_retries_failed_writes_without_requiring_another_status_transition() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result = async {
        case.db
            .run_command(doc! {"create":"machine_status_events","validator":{"status":"offline"}})
            .await?;
        let id = ObjectId::new();
        let now = DateTime::now();
        case.app
            .collection("machines")
            .insert_one(doc! {"_id":id,"user_id":ObjectId::new(),"last_seen_at":now})
            .await?;
        let mut monitor = Monitor::default();
        monitor.tick(&case.app, now).await.map_err(error)?;
        ensure!(events(&case, id).await?.is_empty());
        case.db
            .run_command(doc! {"collMod":"machine_status_events","validator":{}})
            .await?;
        monitor.tick(&case.app, now).await.map_err(error)?;
        monitor.tick(&case.app, now).await.map_err(error)?;
        ensure!(
            events(&case, id).await?.len() == 1
                && events(&case, id).await?[0].get_str("status")? == "online"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn unchanged_status_repairs_baseline_after_history_retention_expires() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result = async {
        let id = ObjectId::new();
        let now = DateTime::now();
        case.app
            .collection("machines")
            .insert_one(doc! {"_id":id,"user_id":ObjectId::new()})
            .await?;
        let mut monitor = Monitor::default();
        monitor.tick(&case.app, now).await.map_err(error)?;
        ensure!(events(&case, id).await?.len() == 1);
        // Simulate the TTL worker deleting its old baseline. Neither process
        // restart nor a status transition should be required to recreate it.
        case.app
            .collection("machine_status_events")
            .delete_many(doc! {"machine_id":id})
            .await?;
        let future = at(now.timestamp_millis() + 370 * 86400 * 1000 + 60_001);
        monitor.tick(&case.app, future).await.map_err(error)?;
        let repaired = events(&case, id).await?;
        ensure!(
            repaired.len() == 1
                && repaired[0].get_str("status")? == "offline"
                && repaired[0].get_datetime("changed_at")? == &future
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    case.db.drop().await?;
    result
}
