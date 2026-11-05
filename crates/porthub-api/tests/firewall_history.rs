use anyhow::{ensure, Result};
use axum::{
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime};
use porthub_api::{config::Config, firewall_history, App};
use serde_json::{json, Value};
mod support;
use support::Case;
#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn mongo_history_migrates_retries_isolates_owners_and_serves_one_hour() -> Result<()> {
    let now = DateTime::now().timestamp_millis() / 1000;
    let samples = json!([
        {"timestamp":now-3601,"in_bytes":999},
        {"timestamp":now-1800,"in_bytes":40,"out_bytes":10,"incoming_ips":["192.0.2.10"],"interval_seconds":1},
        {"timestamp":now-10,"in_bytes":2,"out_bytes":3,"interval_seconds":1}
    ]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let fixture = samples.clone();
    let server = tokio::spawn(async move {
        let app = Router::new().route(
            "/api/ports/traffic/snapshot",
            post(move |headers: HeaderMap, Json(body): Json<Value>| {
                let rows = fixture.clone();
                async move {
                    assert_eq!(headers["x-api-key"], "fixture-firewall-history-key");
                    assert_eq!(body["ports"], json!([8080]));
                    Json(json!({"data":{"8080":rows}}))
                }
            }),
        );
        axum::serve(listener, app).await.unwrap();
    });
    let case = Case::new(Config {
        firewall_base_url: format!("http://{address}/api"),
        firewall_api_key: "fixture-firewall-history-key".into(),
        ..Default::default()
    })
    .await?;
    let result=async {
        let (owner,cookie)=case.user("history-owner@example.invalid","user").await?;
        let (foreign,_)=case.user("history-foreign@example.invalid","user").await?;
        let connection=ObjectId::new(); let machine=ObjectId::new();
        let record=doc!{"_id":connection,"user_id":owner,"machine_id":machine,"external_port":8080,"created_at":DateTime::from_millis((now-7200)*1000)};
        case.app.collection("machines").insert_one(doc!{"_id":machine,"user_id":owner,"name":"History fixture"}).await?;
        case.app.collection("connections").insert_one(record.clone()).await?;
        firewall_history::initialize(&case.app).await?;
        firewall_history::collect(&case.app,0).await?;
        firewall_history::collect(&case.app,now-5).await?;
        ensure!(case.app.collection(firewall_history::COLLECTION).count_documents(doc!{}).await?==2,"Retries must not double-count or retain expired measurements");
        // A fresh application has no in-memory traffic caches or live firewall.
        let fresh=App::new(Config::default(),case.db.clone());
        let history=firewall_history::read(&fresh,&Bson::ObjectId(owner),&[connection]).await?;
        ensure!(history[&connection.to_hex()].len()==2);
        ensure!(firewall_history::read(&fresh,&Bson::ObjectId(foreign),&[connection]).await?.is_empty());
        let page=case.status("GET","/api/inventory/traffic?seconds=3600&page_size=5",&cookie,json!(null),StatusCode::OK).await?;
        let total:f64=page["aggregate"].as_array().unwrap().iter().map(|row|row["in_bytes"].as_f64().unwrap()+row["out_bytes"].as_f64().unwrap()).sum();
        ensure!(total==55.,"One-hour dashboard must include the older sample: {page}");
        let expanded=case.status("GET",&format!("/api/inventory/traffic?seconds=3600&expanded={connection}"),&cookie,json!(null),StatusCode::OK).await?;
        ensure!(expanded["data"][0]["traffic"][0]["incoming_ips"][0]=="192.0.2.10");
        let mut corrected=samples.as_array().unwrap().clone(); corrected[1]["in_bytes"]=json!(45);
        firewall_history::persist(&case.app,&record,&corrected).await?;
        ensure!(firewall_history::read(&fresh,&Bson::ObjectId(owner),&[connection]).await?[&connection.to_hex()][0]["in_bytes"]==45.);
        // A firewall IPC outage does not prevent Mongo-backed history reads.
        server.abort();
        tokio::task::yield_now().await;
        ensure!(firewall_history::collect(&case.app,now-5).await.is_err());
        ensure!(firewall_history::read(&fresh,&Bson::ObjectId(owner),&[connection]).await?[&connection.to_hex()].len()==2);
        case.app.collection("connections").delete_one(doc!{"_id":connection}).await?;
        firewall_history::collect(&case.app,0).await?;
        ensure!(case.app.collection(firewall_history::COLLECTION).count_documents(doc!{}).await?==0);
        Ok(())
    }.await;
    server.abort();
    case.db.drop().await?;
    result
}
