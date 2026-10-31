use anyhow::{ensure, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId};
use porthub_api::{config::Config, domain::traffic_routes};
use serde_json::json;
mod support;
use support::Case;

#[test]
fn proxy_tags_are_normalized_bounded_and_optional_for_legacy_clients() {
    let body = json!({"name":"app","hosts":["app.example"],"target_url":"https://example.com","tags":[" RolloutTag ","ROLLOUTTAG","camera"]});
    assert_eq!(
        traffic_routes::parse(body.clone()).unwrap_or_else(|error|panic!("{}",error.detail)).tags,
        vec!["rollouttag", "camera"]
    );
    for tags in [
        json!("camera"),
        json!([42]),
        json!(["x".repeat(41)]),
        json!(["bad\nvalue"]),
        json!(vec!["tag"; 21]),
    ] {
        let mut invalid = body.clone();
        invalid["tags"] = tags;
        assert!(traffic_routes::parse(invalid).is_err());
    }
}

#[tokio::test]
#[ignore = "requires isolated MongoDB"]
async fn proxy_tags_and_live_inherited_groups_filter_in_mongo_before_pagination() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let (owner, cookie) = case.user("proxy-tags@example.test", "user").await?;
    let (foreign, _) = case.user("foreign-tags@example.test", "user").await?;
    let groups = [ObjectId::new(), ObjectId::new(), ObjectId::new()];
    case.app
        .collection("machine_groups")
        .insert_many([
            doc! {"_id":groups[0],"user_id":owner,"name":"Production"},
            doc! {"_id":groups[1],"user_id":owner,"name":"Fallback"},
            doc! {"_id":groups[2],"user_id":foreign,"name":"Foreign secret"},
        ])
        .await?;
    let machines = [ObjectId::new(), ObjectId::new(), ObjectId::new()];
    case.app
        .collection("machines")
        .insert_many([
            doc! {"_id":machines[0],"user_id":owner,"group_ids":[groups[0]]},
            doc! {"_id":machines[1],"user_id":owner,"group_ids":[groups[1].to_hex()]},
            doc! {"_id":machines[2],"user_id":foreign,"group_ids":[groups[2]]},
        ])
        .await?;
    let proxy = ObjectId::new();
    case.app.collection("traffic_routes").insert_many([
        doc!{"_id":proxy,"user_id":owner,"name":"app.example","hosts":["app.example"],"tags":["rollouttag","camera"],
            "bindings":[{"connection":{"machine_id":machines[0].to_hex()}},{"connection":{"machine_id":machines[2].to_hex()}},{"connection":{"machine_id":machines[1].to_hex()}}]},
        doc!{"_id":ObjectId::new(),"user_id":owner,"name":"other.example","hosts":["other.example"],"tags":["other"]},
        doc!{"_id":ObjectId::new(),"user_id":foreign,"name":"hidden.example","tags":["foreignsecret"]},
    ]).await?;
    let page = case
        .status(
            "GET",
            "/api/inventory/proxies?tag=rollouttag&page_size=1",
            &cookie,
            json!(null),
            StatusCode::OK,
        )
        .await?;
    ensure!(page["pagination"]["total"] == 1, "{page}");
    let inherited = page["data"][0]["inherited_groups"].as_array().unwrap();
    ensure!(
        inherited.len() == 2 && !page.to_string().contains("Foreign secret"),
        "{page}"
    );
    let filtered = case
        .status(
            "GET",
            &format!("/api/inventory/proxies?machine_group={}", groups[1]),
            &cookie,
            json!(null),
            StatusCode::OK,
        )
        .await?;
    ensure!(filtered["pagination"]["total"] == 1, "{filtered}");
    let tags = case
        .status(
            "GET",
            "/api/inventory/proxy-tags?options=true&q=rollout",
            &cookie,
            json!(null),
            StatusCode::OK,
        )
        .await?;
    ensure!(
        tags["pagination"]["total"] == 1 && tags["data"][0]["name"] == "rollouttag",
        "{tags}"
    );
    let search = case
        .status(
            "GET",
            "/api/inventory/proxies?q=rollouttag",
            &cookie,
            json!(null),
            StatusCode::OK,
        )
        .await?;
    ensure!(search["pagination"]["total"] == 1, "{search}");
    case.app
        .collection("machines")
        .update_one(doc! {"_id":machines[1]}, doc! {"$set":{"group_ids":[]}})
        .await?;
    let changed = case
        .status(
            "GET",
            &format!("/api/inventory/proxies?machine_group={}", groups[1]),
            &cookie,
            json!(null),
            StatusCode::OK,
        )
        .await?;
    ensure!(
        changed["pagination"]["total"] == 0,
        "group inheritance must reflect current machine groups"
    );
    case.db.drop().await?;
    Ok(())
}
