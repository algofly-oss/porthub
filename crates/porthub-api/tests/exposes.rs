use anyhow::{ensure, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use porthub_api::{config::Config, routes::exposes::recover_due};
use serde_json::json;
mod support;
use support::Case;

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn temporary_exposures_enforce_ownership_reservations_and_expiry() -> Result<()> {
    let case = Case::new(Config {
        external_port_range: Some((31000, 31002)),
        service_domain: "services.example.invalid".into(),
        gateway_public_ip: Some("192.0.2.10".into()),
        public_base_url: "https://gateway.example.invalid".into(),
        proxy_domain_suffix: "apps.example.invalid".into(),
        ..Config::default()
    }).await?;
    let result = async {
        let (owner, _) = case.user("expose@example.invalid", "user").await?;
        let (other, _) = case.user("other@example.invalid", "user").await?;
        let (machine, foreign) = (ObjectId::new(), ObjectId::new());
        for (id, user, token) in [(machine, owner, "local-test"), (foreign, other, "foreign-test")] {
            case.app.collection("machines").insert_one(doc! {"_id":id,"user_id":user,"enabled":true,"token":token}).await?;
        }
        case.app.collection("connections").insert_one(doc! {"_id":ObjectId::new(),"external_port":31000_i64,"user_id":other}).await?;
        let endpoint = "/api/machines/client/expose";
        let mut request = json!({"machine_id":machine.to_hex(),"token":"wrong","request_id":"0123456789abcdef0123456789abcdef","local_port":8000,"external_port":31001,"subdomain":"demo"});
        case.status("POST", endpoint, "", request.clone(), StatusCode::GONE).await?;
        request["token"] = json!("local-test");
        request["external_port"] = json!(31000);
        case.status("POST", endpoint, "", request.clone(), StatusCode::BAD_REQUEST).await?;
        request["external_port"] = json!(31001);
        let created = case.status("POST", endpoint, "", request.clone(), StatusCode::OK).await?;
        let id = created["data"]["exposure_id"].as_str().unwrap();
        ensure!(created["data"]["external_port"] == 31001);
        ensure!(created["data"]["tcp_url"] == "services.example.invalid:31001");
        ensure!(case.app.collection("traffic_routes").count_documents(doc! {"exposure_id":id,"temporary":true,"user_id":owner}).await? == 1);
        let repeated = case.status("POST", endpoint, "", request.clone(), StatusCode::OK).await?;
        ensure!(repeated["data"]["exposure_id"] == id);
        request["request_id"] = json!("1123456789abcdef0123456789abcdef");
        case.status("POST", endpoint, "", request.clone(), StatusCode::BAD_REQUEST).await?;
        // A proxy conflict must roll back its newly allocated public port.
        request["external_port"] = json!(31002);
        case.status("POST", endpoint, "", request, StatusCode::BAD_REQUEST).await?;
        ensure!(case.app.collection("connections").count_documents(doc! {"external_port":31002_i64}).await? == 0);
        let foreign_request = json!({"machine_id":foreign.to_hex(),"token":"foreign-test","exposure_id":id});
        case.status("POST", &format!("{endpoint}/renew"), "", foreign_request.clone(), StatusCode::GONE).await?;
        case.status("POST", &format!("{endpoint}/close"), "", foreign_request, StatusCode::OK).await?;
        ensure!(case.app.collection("connections").count_documents(doc! {"exposure_id":id}).await? == 1);
        let owned = json!({"machine_id":machine.to_hex(),"token":"local-test","exposure_id":id});
        case.status("POST", &format!("{endpoint}/renew"), "", owned.clone(), StatusCode::OK).await?;
        ensure!(recover_due(&case.app).await.map_err(|_| anyhow::anyhow!("exposure cleanup failed"))?.is_some());
        case.app.collection("connections").update_one(doc! {"exposure_id":id}, doc! {"$set":{"lease_expires_at":DateTime::from_millis(0)}}).await?;
        // An expired lease cannot be revived before the cleanup worker runs.
        case.status("POST", &format!("{endpoint}/renew"), "", owned.clone(), StatusCode::GONE).await?;
        ensure!(recover_due(&case.app).await.map_err(|_| anyhow::anyhow!("exposure cleanup failed"))?.is_none());
        ensure!(case.app.collection("connections").count_documents(doc! {"exposure_id":id}).await? == 0);
        ensure!(case.app.collection("traffic_routes").count_documents(doc! {"exposure_id":id}).await? == 0);
        case.status("POST", &format!("{endpoint}/close"), "", owned, StatusCode::OK).await?;
        // More than one cleanup batch must schedule its remaining expired work.
        for _ in 0..33 {
            case.app.collection("connections").insert_one(doc! {"_id":ObjectId::new(),"machine_id":machine,"temporary":true,"exposure_id":uuid::Uuid::new_v4().to_string(),"lease_expires_at":DateTime::from_millis(0)}).await?;
        }
        ensure!(recover_due(&case.app).await.map_err(|_| anyhow::anyhow!("exposure cleanup failed"))?.is_some());
        ensure!(case.app.collection("connections").count_documents(doc! {"temporary":true}).await? == 1);
        ensure!(recover_due(&case.app).await.map_err(|_| anyhow::anyhow!("exposure cleanup failed"))?.is_none());
        ensure!(case.app.collection("connections").count_documents(doc! {}).await? == 1);
        Ok::<_, anyhow::Error>(())
    }.await;
    case.db.drop().await?;
    result
}
