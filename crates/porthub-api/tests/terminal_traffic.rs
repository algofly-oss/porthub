use anyhow::{ensure, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId};
use porthub_api::config::Config;
use porthub_terminal::traffic_report::Summary;
use serde_json::{json, Value};
mod support;
use support::Case;
const PATH: &str = "/api/machines/client/terminal-traffic";
fn body(id: ObjectId, revision: u64, bytes: u64) -> Value {
    let mut summary = Summary {
        instance: "a".repeat(32),
        revision,
        ..Default::default()
    };
    summary.counters.input_bytes = bytes;
    summary.counters.direct_udp_sent_bytes = bytes * 2;
    json!({"machine_id":id.to_hex(),"token":"fixture-only","summary":summary})
}
#[tokio::test]
#[ignore = "requires isolated MongoDB"]
async fn authenticated_rollups_are_atomic_idempotent_and_bound_to_machine_owner() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result = exercise(&case).await;
    case.db.drop().await?;
    result
}
async fn exercise(case: &Case) -> Result<()> {
    let (owner, owner_cookie) = case.user("traffic-owner@example.test", "user").await?;
    let (other, other_cookie) = case.user("traffic-other@example.test", "admin").await?;
    let id = ObjectId::new();
    case.app
        .collection("machines")
        .insert_one(doc! {"_id":id,"user_id":owner,"token":"fixture-only","enabled":true})
        .await?;
    let first = case
        .status("POST", PATH, "", body(id, 1, 100), StatusCode::OK)
        .await?;
    ensure!(first["accepted"] == true);
    let first = case
        .app
        .collection("terminal_traffic")
        .find_one(doc! {"machine_id":id})
        .await?
        .unwrap();
    ensure!(first.get_object_id("owner_id")? == owner);
    ensure!(
        first.get_array("recent")?[0]
            .as_document()
            .unwrap()
            .get_i64("pty_input")?
            == 0,
        "first snapshot is a baseline, not a fabricated spike"
    );
    let next = body(id, 2, 113);
    ensure!(
        case.status("POST", PATH, "", next.clone(), StatusCode::OK)
            .await?["accepted"]
            == true
    );
    ensure!(case.status("POST", PATH, "", next, StatusCode::OK).await?["accepted"] == false);
    ensure!(
        case.status("POST", PATH, "", body(id, 1, 100), StatusCode::OK)
            .await?["accepted"]
            == false
    );
    case.status("POST", PATH, "", body(id, 2, 114), StatusCode::CONFLICT)
        .await?;
    case.status("POST", PATH, "", body(id, 3, 112), StatusCode::CONFLICT)
        .await?;
    // Simultaneous reports may arrive out of order; neither may count a delta twice.
    let (a, b) = tokio::join!(
        case.call("POST", PATH, "", body(id, 10, 150), &[]),
        case.call("POST", PATH, "", body(id, 11, 160), &[])
    );
    ensure!(a?.0 == StatusCode::OK && b?.0 == StatusCode::OK);
    let saved = case
        .app
        .collection("terminal_traffic")
        .find_one(doc! {"machine_id":id})
        .await?
        .unwrap();
    for name in ["recent", "minutes", "hours", "days"] {
        let sum: i64 = saved
            .get_array(name)?
            .iter()
            .map(|row| row.as_document().unwrap().get_i64("pty_input").unwrap())
            .sum();
        ensure!(
            sum == 60,
            "{name}: replay/concurrency changed the measured delta: {sum}"
        );
    }
    ensure!(saved.get_document("summary")?.get_i64("revision")? == 11);
    ensure!(
        !format!("{saved:?}").contains("fixture-only"),
        "credentials must not be persisted in measurements"
    );
    let mut bad = body(id, 12, 170);
    bad["owner_id"] = other.to_hex().into();
    case.status("POST", PATH, "", bad, StatusCode::BAD_REQUEST)
        .await?;
    let mut bad = body(id, 12, 170);
    bad["token"] = "wrong-token".into();
    case.status("POST", PATH, "", bad, StatusCode::GONE).await?;
    case.app
        .collection("machines")
        .update_one(doc! {"_id":id}, doc! {"$set":{"enabled":false}})
        .await?;
    case.status("POST", PATH, "", body(id, 12, 170), StatusCode::FORBIDDEN)
        .await?;
    let own = case
        .status(
            "GET",
            "/api/terminal/traffic?range=1h",
            &owner_cookie,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
    ensure!(own["points"].as_array().unwrap().len() <= 60);
    ensure!(
        own["points"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["pty_input"].as_i64().unwrap())
            .sum::<i64>()
            == 60
    );
    for range in ["10m", "24h", "7d", "30d"] {
        let response = case
            .status(
                "GET",
                &format!("/api/terminal/traffic?range={range}"),
                &owner_cookie,
                Value::Null,
                StatusCode::OK,
            )
            .await?;
        let points = response["points"].as_array().unwrap();
        ensure!(points.len() <= 120);
        ensure!(
            points
                .iter()
                .map(|point| point["pty_input"].as_i64().unwrap())
                .sum::<i64>()
                == 60
        );
    }
    let admin = case
        .status(
            "GET",
            "/api/terminal/traffic?range=1h",
            &other_cookie,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
    ensure!(
        admin["points"].as_array().unwrap().is_empty(),
        "administrator role must not expose another account's traffic"
    );
    let filtered = case
        .status(
            "GET",
            &format!("/api/terminal/traffic?machine_id={id}"),
            &other_cookie,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
    ensure!(filtered["points"].as_array().unwrap().is_empty());
    case.status(
        "GET",
        "/api/terminal/traffic?range=forever",
        &owner_cookie,
        Value::Null,
        StatusCode::BAD_REQUEST,
    )
    .await?;
    // A transfer starts a new account-scoped baseline, never inheriting the old
    // owner's cumulative totals, even when the service instance is unchanged.
    case.app
        .collection("machines")
        .update_one(
            doc! {"_id":id},
            doc! {"$set":{"enabled":true,"user_id":other}},
        )
        .await?;
    case.status("POST", PATH, "", body(id, 12, 170), StatusCode::OK)
        .await?;
    ensure!(
        case.app
            .collection("terminal_traffic")
            .count_documents(doc! {"machine_id":id})
            .await?
            == 2
    );
    let transferred = case
        .app
        .collection("terminal_traffic")
        .find_one(doc! {"machine_id":id,"owner_id":other})
        .await?
        .unwrap();
    ensure!(
        transferred.get_array("minutes")?[0]
            .as_document()
            .unwrap()
            .get_i64("pty_input")?
            == 0
    );
    let retired = case
        .status(
            "GET",
            "/api/terminal/traffic?range=1h",
            &owner_cookie,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
    ensure!(
        retired["points"].as_array().unwrap().is_empty(),
        "transferred machine must disappear from previous owner's traffic"
    );
    case.app
        .collection("machines")
        .update_one(doc! {"_id":id}, doc! {"$set":{"deletion_pending":true}})
        .await?;
    let deleted = case
        .status(
            "GET",
            "/api/terminal/traffic?range=1h",
            &other_cookie,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
    ensure!(deleted["points"].as_array().unwrap().is_empty());
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated MongoDB"]
async fn legacy_relay_samples_do_not_claim_host_measurement_coverage() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result = async {
        let (owner, cookie) = case.user("legacy-terminal@example.test", "user").await?;
        let id = ObjectId::new();
        case.app
            .collection("machines")
            .insert_one(doc! {"_id":id,"user_id":owner,"token":"fixture-only","enabled":true})
            .await?;
        let mut summary = Summary {
            instance: "c".repeat(32),
            revision: 1,
            active_sessions: 1,
            ..Default::default()
        };
        for revision in 1..=2 {
            summary.revision = revision;
            summary.relay_sent_payload_bytes = revision * 13;
            case.status(
                "POST",
                PATH,
                "",
                json!({"machine_id":id.to_hex(),"token":"fixture-only","summary":summary}),
                StatusCode::OK,
            )
            .await?;
        }
        let read = case
            .status(
                "GET",
                "/api/terminal/traffic?range=1h",
                &cookie,
                Value::Null,
                StatusCode::OK,
            )
            .await?;
        let points = read["points"].as_array().unwrap();
        ensure!(
            !points.is_empty()
                && points
                    .iter()
                    .all(|point| point["host_reports"] == 0 && point["unreported_hosts"] == 1)
        );
        ensure!(
            points
                .iter()
                .map(|point| point["relay_sent"].as_u64().unwrap())
                .sum::<u64>()
                == 13
        );
        // A zero-byte modern sample supplies real coverage; it must be distinct
        // from a legacy host whose unknown counters merely default to zero.
        summary.revision = 3;
        summary.reported_sessions = 1;
        summary.active_reporting_sessions = 1;
        case.status(
            "POST",
            PATH,
            "",
            json!({"machine_id":id.to_hex(),"token":"fixture-only","summary":summary}),
            StatusCode::OK,
        )
        .await?;
        let read = case
            .status(
                "GET",
                "/api/terminal/traffic?range=1h",
                &cookie,
                Value::Null,
                StatusCode::OK,
            )
            .await?;
        ensure!(read["points"]
            .as_array()
            .unwrap()
            .iter()
            .any(|point| point["host_reports"] == 1 && point["pty_input"] == 0));
        Ok(())
    }
    .await;
    case.db.drop().await?;
    result
}
