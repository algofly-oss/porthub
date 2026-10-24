//! One bounded-batch monitor per core. History is persisted only on transitions;
//! heartbeat races cannot claim stale instant alerts. Telegram I/O holds no
//! global configuration locks and uses the existing bounded HTTP client.
use crate::{
    domain::{inventory, telegram},
    error::ApiResult,
    store, App,
};
use futures_util::TryStreamExt;
use mongodb::{
    bson::{doc, oid::ObjectId, Bson, DateTime, Document},
    options::IndexOptions,
    IndexModel,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};
use tokio::sync::watch;

const RETENTION: Duration = Duration::from_secs(370 * 24 * 60 * 60);
const DIGEST_PERIOD: Duration = Duration::from_secs(600);

pub fn interval(app: &App) -> Duration {
    Duration::from_secs((app.config.machine_online_ttl_millis / 2000).clamp(5, 30) as u64)
}
fn alert_after(app: &App) -> i64 {
    app.config
        .machine_online_ttl_millis
        .saturating_add(app.config.machine_offline_alert_grace_millis)
}
pub async fn initialize(app: &App, now: DateTime) -> ApiResult<()> {
    app.collection("machine_status_events")
        .create_index(
            IndexModel::builder()
                .keys(doc! {"machine_id":1,"changed_at":-1})
                .build(),
        )
        .await?;
    app.collection("machines")
        .create_index(
            IndexModel::builder()
                .keys(doc! {"telegram_offline_alerted":1,"last_seen_at":1})
                .build(),
        )
        .await?;
    app.collection("machine_status_events")
        .create_index(
            IndexModel::builder()
                .keys(doc! {"changed_at":1})
                .options(IndexOptions::builder().expire_after(RETENTION).build())
                .build(),
        )
        .await?;
    // Existing offline machines should not generate a startup alert storm.
    app.collection("machines").update_many(
        doc! {"telegram_offline_alerted":{"$exists":false},"last_seen_at":{"$lt":DateTime::from_millis(now.timestamp_millis().saturating_sub(alert_after(app)))}},
        doc! {"$set":{"telegram_offline_alerted":true}}).await?;
    Ok(())
}

#[derive(Clone, Copy)]
struct Entry {
    online: bool,
    history_due: i64,
}
#[derive(Default)]
pub struct Monitor {
    previous: BTreeMap<ObjectId, Entry>,
}
impl Monitor {
    pub async fn tick(&mut self, app: &App, now: DateTime) -> ApiResult<()> {
        let mut machines = app
            .collection("machines")
            .find(doc! {"deletion_pending":{"$ne":true}})
            .batch_size(100)
            .await?;
        let mut seen = BTreeSet::new();
        while let Some(machine) = machines.try_next().await? {
            let Ok(id) = machine.get_object_id("_id") else {
                continue;
            };
            seen.insert(id);
            let online = matches!(
                inventory::status_at(app, &machine, now),
                "online" | "auth_required"
            );
            let previous = self.previous.get(&id).copied();
            let changed = previous.is_some_and(|entry| entry.online != online);
            if changed {
                app.notify_status(&machine).await;
            }
            let needs_history = previous.is_none_or(|entry| {
                entry.online != online || entry.history_due <= now.timestamp_millis()
            });
            let history_due = if needs_history {
                match sync_history(app, &machine, online, now).await {
                    Ok(due) => due,
                    Err(error) => {
                        tracing::warn!(detail=%error.detail,"machine history update failed");
                        now.timestamp_millis()
                    }
                }
            } else {
                previous.map_or(now.timestamp_millis(), |entry| entry.history_due)
            };
            self.previous.insert(
                id,
                Entry {
                    online,
                    history_due,
                },
            );
        }
        self.previous.retain(|id, _| seen.contains(id));
        Ok(())
    }
}
fn history_due(changed: DateTime, now: DateTime) -> i64 {
    // Allow the MongoDB TTL sweep to remove an expired baseline, then repair it
    // without querying unchanged history on every presence scan.
    changed
        .timestamp_millis()
        .saturating_add(RETENTION.as_millis() as i64)
        .saturating_add(60_000)
        .max(now.timestamp_millis().saturating_add(60_000))
}
async fn sync_history(
    app: &App,
    machine: &Document,
    online: bool,
    now: DateTime,
) -> ApiResult<i64> {
    let status = if online { "online" } else { "offline" };
    let latest = app
        .collection("machine_status_events")
        .find_one(doc! {"machine_id":machine.get("_id")})
        .sort(doc! {"changed_at":-1,"_id":-1})
        .await?;
    if latest
        .as_ref()
        .is_some_and(|latest| latest.get_str("status") == Ok(status))
    {
        return Ok(history_due(
            latest
                .as_ref()
                .and_then(|latest| latest.get_datetime("changed_at").ok())
                .copied()
                .unwrap_or(now),
            now,
        ));
    }
    app.collection("machine_status_events")
        .insert_one(doc! {"machine_id":machine.get("_id"),
        "user_id":machine.get("user_id"),"status":status,"changed_at":now})
        .await?;
    Ok(history_due(now, now))
}

pub fn last_seen(value: Option<&Bson>, now: DateTime) -> String {
    let Some(Bson::DateTime(seen)) = value else {
        return "never".into();
    };
    let seconds = now
        .timestamp_millis()
        .saturating_sub(seen.timestamp_millis())
        .max(0)
        / 1000;
    match seconds {
        0..60 => "just now".into(),
        60..3600 => format!("{}m ago", seconds / 60),
        3600..86400 => format!("{}h ago", seconds / 3600),
        _ => format!("{}d ago", seconds / 86400),
    }
}
fn name(machine: &Document) -> String {
    let text = store::string(machine, "name");
    let text = if text.is_empty() { "Machine" } else { text };
    // Escape before HTML delivery; bound names before escaping so one digest
    // line always fits Telegram's limit, including astral Unicode characters.
    text.chars()
        .take(256)
        .map(|ch| match ch {
            '&' => "&amp;".into(),
            '<' => "&lt;".into(),
            '>' => "&gt;".into(),
            ch => ch.to_string(),
        })
        .collect()
}
fn chats(user: &Document) -> &[Bson] {
    user.get_array("telegram_chat_ids")
        .map(Vec::as_slice)
        .unwrap_or_default()
}
async fn deliver(app: &App, user: &Document, text: &str) {
    let (_, failed) = telegram::send(
        app,
        store::string(user, "telegram_bot_token"),
        chats(user),
        text,
    )
    .await;
    if !failed.is_empty() {
        tracing::warn!(
            failed_chats = failed.len(),
            "machine notification delivery failed"
        );
    }
}
pub async fn process_alert(app: &App, machine: &Document, now: DateTime) -> ApiResult<()> {
    if machine.get_bool("enabled") == Ok(false)
        || machine.get_bool("telegram_alerts_excluded") == Ok(true)
    {
        return Ok(());
    }
    let offline = inventory::status_at(app, machine, now) == "offline";
    let alerted = machine.get_bool("telegram_offline_alerted") == Ok(true);
    if offline == alerted {
        return Ok(());
    }
    if offline
        && machine.get_datetime("last_seen_at").map_or(true, |seen| {
            now.timestamp_millis()
                .saturating_sub(seen.timestamp_millis())
                < alert_after(app)
        })
    {
        return Ok(());
    }
    let claim = app.collection("machines").update_one(doc! {"_id":machine.get("_id"),
        "deletion_pending":{"$ne":true},"enabled":{"$ne":false},"telegram_alerts_excluded":{"$ne":true},
        "last_seen_at":machine.get("last_seen_at"),
        "telegram_offline_alerted":if alerted { doc! {"$eq":true} } else { doc! {"$ne":true} }},
        doc! {"$set":{"telegram_offline_alerted":offline}}).await?;
    if claim.modified_count == 0 {
        return Ok(());
    }
    let Some(user) = app
        .collection("users")
        .find_one(doc! {"_id":machine.get("user_id")})
        .await?
    else {
        return Ok(());
    };
    if user.get_bool("telegram_alerts_enabled") != Ok(true)
        || user.get_bool("telegram_instant_alerts_enabled") == Ok(false)
    {
        return Ok(());
    }
    let text = if offline {
        format!(
            "🔴 <b>{}</b> went offline (last seen {})",
            name(machine),
            last_seen(machine.get("last_seen_at"), now)
        )
    } else {
        format!("🟢 <b>{}</b> is back online", name(machine))
    };
    deliver(app, &user, &text).await;
    Ok(())
}

/// Independent from history/presence: slow Telegram delivery cannot delay
/// offline notifications to browsers. Only eligible transitions are scanned.
pub async fn alerts_once(app: &App, now: DateTime) -> ApiResult<()> {
    let offline = DateTime::from_millis(now.timestamp_millis().saturating_sub(alert_after(app)));
    let online = DateTime::from_millis(
        now.timestamp_millis()
            .saturating_sub(app.config.machine_online_ttl_millis),
    );
    let mut machines = app.collection("machines").find(doc! {
        "deletion_pending":{"$ne":true},"enabled":{"$ne":false},"telegram_alerts_excluded":{"$ne":true},
        "$or":[
            {"telegram_offline_alerted":{"$ne":true},"last_seen_at":{"$lte":offline,"$lt":online}},
            {"telegram_offline_alerted":true,"last_seen_at":{"$gte":online}}
        ]}).batch_size(100).await?;
    while let Some(machine) = machines.try_next().await? {
        if let Err(error) = process_alert(app, &machine, now).await {
            tracing::warn!(detail=%error.detail,"machine alert update failed");
        }
    }
    Ok(())
}

fn digest_interval(user: &Document) -> i64 {
    let hours = match user.get("telegram_digest_interval_hours") {
        Some(Bson::Int32(value)) => i64::from(*value),
        Some(Bson::Int64(value)) => *value,
        Some(Bson::Double(value)) if value.is_finite() => *value as i64,
        _ => 6,
    };
    let hours = if hours == 0 { 6 } else { hours.max(1) };
    hours.saturating_mul(3_600_000)
}

pub async fn digest_once(app: &App, now: DateTime) -> ApiResult<()> {
    let mut users = app
        .collection("users")
        .find(doc! {"telegram_alerts_enabled":true,
        "telegram_digest_enabled":true,"telegram_bot_token":{"$exists":true,"$ne":""}})
        .batch_size(100)
        .await?;
    while let Some(user) = users.try_next().await? {
        if chats(&user).is_empty() || store::string(&user, "telegram_bot_token").trim().is_empty() {
            continue;
        }
        if user
            .get_datetime("telegram_last_batch_alert_at")
            .is_ok_and(|last| {
                now.timestamp_millis()
                    .saturating_sub(last.timestamp_millis())
                    < digest_interval(&user)
            })
        {
            continue;
        }
        if let Err(error) = digest_user(app, &user, now).await {
            tracing::warn!(detail=%error.detail,"machine digest update failed");
        }
    }
    Ok(())
}
async fn digest_user(app: &App, user: &Document, now: DateTime) -> ApiResult<()> {
    // Claim one period before network I/O. An interrupted or failed send is not
    // replayed automatically. This avoids duplicate scheduled digests, but a
    // process crash after claiming can skip that digest period.
    let claim = app.collection("users").update_one(doc! {"_id":user.get("_id"),
        "telegram_alerts_enabled":true,"telegram_digest_enabled":true,
        "telegram_bot_token":user.get("telegram_bot_token"),"telegram_chat_ids":user.get("telegram_chat_ids"),
        "telegram_digest_interval_hours":user.get("telegram_digest_interval_hours"),
        "telegram_last_batch_alert_at":user.get("telegram_last_batch_alert_at")},
        doc! {"$set":{"telegram_last_batch_alert_at":now}}).await?;
    if claim.modified_count == 0 {
        return Ok(());
    }
    let mut machines = app.collection("machines").find(doc! {"user_id":user.get("_id"),
        "deletion_pending":{"$ne":true},"enabled":{"$ne":false},"telegram_alerts_excluded":{"$ne":true}}).batch_size(100).await?;
    let header = "📡 <b>Machines still offline</b>";
    let mut text = header.to_owned();
    while let Some(machine) = machines.try_next().await? {
        if inventory::status_at(app, &machine, now) != "offline" {
            continue;
        }
        let line = format!(
            "\n• {} — last seen {}",
            name(&machine),
            last_seen(machine.get("last_seen_at"), now)
        );
        if text.encode_utf16().count() + line.encode_utf16().count() > 4096 {
            deliver(app, user, &text).await;
            text = header.into();
        }
        text.push_str(&line);
    }
    if text != header {
        deliver(app, user, &text).await;
    }
    Ok(())
}

pub async fn run(app: Arc<App>, mut stop: watch::Receiver<bool>) {
    let mut monitor = Monitor::default();
    loop {
        if *stop.borrow() {
            return;
        }
        tokio::select! {
            biased;
            _ = stop.changed() => return,
            result = monitor.tick(&app,DateTime::now()) => {
                if let Err(error) = result { tracing::warn!(detail=%error.detail,"machine monitor failed"); }
            }
        }
        tokio::select! { _ = stop.changed() => return, _ = tokio::time::sleep(interval(&app)) => {} }
    }
}
pub async fn run_digest(app: Arc<App>, mut stop: watch::Receiver<bool>) {
    loop {
        if *stop.borrow() {
            return;
        }
        tokio::select! {
            biased;
            _ = stop.changed() => return,
            result = digest_once(&app,DateTime::now()) => {
                if let Err(error) = result { tracing::warn!(detail=%error.detail,"machine digest failed"); }
            }
        }
        tokio::select! { _ = stop.changed() => return, _ = tokio::time::sleep(DIGEST_PERIOD) => {} }
    }
}

pub async fn run_alerts(app: Arc<App>, mut stop: watch::Receiver<bool>) {
    loop {
        if *stop.borrow() {
            return;
        }
        tokio::select! {
            biased;
            _ = stop.changed() => return,
            result = alerts_once(&app,DateTime::now()) => {
                if let Err(error) = result { tracing::warn!(detail=%error.detail,"machine alert scan failed"); }
            }
        }
        tokio::select! { _ = stop.changed() => return, _ = tokio::time::sleep(interval(&app)) => {} }
    }
}
