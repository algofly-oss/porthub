use anyhow::{ensure, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId};
use porthub_api::{
    config::Config,
    domain::{enrollment::Network, private_networks},
};
use serde_json::json;
mod support;
use support::Case;

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn tenants_receive_distinct_ranges_and_cannot_claim_overlaps() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result = async {
        let (a, cookie_a) = case.user("range-a@test.invalid", "user").await?;
        let (b, cookie_b) = case.user("range-b@test.invalid", "user").await?;
        let a_id = a.to_hex();
        let b_id = b.to_hex();
        let (first, second) = tokio::join!(
            private_networks::ensure(&case.app, &a_id),
            private_networks::ensure(&case.app, &b_id)
        );
        let first = first.map_err(|e| anyhow::anyhow!("{}", e.detail))?;
        let second = second.map_err(|e| anyhow::anyhow!("{}", e.detail))?;
        let first_range = Network::parse(first.get_str("cidr")?).unwrap();
        let second_range = Network::parse(second.get_str("cidr")?).unwrap();
        ensure!(!first_range.overlaps(second_range));
        ensure!(
            private_networks::ensure(&case.app, &a_id)
                .await
                .map_err(|e| anyhow::anyhow!("{}", e.detail))?
                == first
        );
        let path = format!("/api/access/network?workspace={b}");
        case.status(
            "PUT",
            &path,
            &cookie_b,
            json!({"cidr":first_range.cidr(),"dns_suffix":"phub"}),
            StatusCode::CONFLICT,
        )
        .await?;
        case.status(
            "PUT",
            &path,
            &cookie_b,
            json!({"cidr":"10.203.0.0/16","dns_suffix":"phub"}),
            StatusCode::CONFLICT,
        )
        .await?;
        case.status(
            "PUT",
            &path,
            &cookie_b,
            json!({"cidr":"192.168.77.0/24","dns_suffix":"phub"}),
            StatusCode::OK,
        )
        .await?;
        // A foreign account cannot use the network endpoint to change the owner.
        case.status(
            "PUT",
            &format!("/api/access/network?workspace={a}"),
            &cookie_b,
            json!({"cidr":"192.168.78.0/24","dns_suffix":"phub"}),
            StatusCode::FORBIDDEN,
        )
        .await?;
        // Existing peer addresses stay reserved even after preferences change.
        case.app
            .collection("private_peers")
            .insert_one(doc! {"_id":"retained", "workspace_id":b, "ip":"192.168.79.12"})
            .await?;
        case.status(
            "PUT",
            &format!("/api/access/network?workspace={a}"),
            &cookie_a,
            json!({"cidr":"192.168.79.0/24","dns_suffix":"phub"}),
            StatusCode::CONFLICT,
        )
        .await?;
        Ok(())
    }
    .await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn legacy_addresses_are_preserved_and_reserved_for_new_tenants() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result = async {
        let legacy = ObjectId::new();
        case.app
            .collection("private_peers")
            .insert_one(doc! {"_id":"legacy", "workspace_id":legacy, "ip":"10.203.0.10"})
            .await?;
        let fresh = private_networks::ensure(&case.app, &ObjectId::new().to_hex())
            .await
            .map_err(|e| anyhow::anyhow!("{}", e.detail))?;
        ensure!(fresh.get_str("cidr")? != "10.203.0.0/24");
        let retained = private_networks::ensure(&case.app, &legacy.to_hex())
            .await
            .map_err(|e| anyhow::anyhow!("{}", e.detail))?;
        ensure!(retained.get_str("cidr")? == "10.203.0.0/24");
        Ok(())
    }
    .await;
    case.db.drop().await?;
    result
}
