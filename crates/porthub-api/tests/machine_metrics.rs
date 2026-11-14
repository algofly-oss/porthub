use anyhow::{ensure, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use serde_json::{json, Value};
mod support;
use support::Case;
#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn authenticated_reports_owner_scoping_minute_retention_and_history() -> Result<()> {
    let case = Case::new(Default::default()).await?;
    let result:Result<()>=async{
  let(owner,cookie)=case.user("metrics-owner@example.invalid","user").await?;
  let(_,other)=case.user("metrics-other@example.invalid","user").await?;
  let machine=ObjectId::new();let id=machine.to_hex();
  case.app.collection("machines").insert_one(doc!{"_id":machine,"name":"Metrics desktop","token":"fixture-metrics","user_id":owner,"enabled":true}).await?;
  let sample=json!({"cpu":42.5,"cores":4,"ram":{"used":4096,"total":8192},"disk":{"used":20,"total":100},"gpus":[{"name":"Test GPU","utilization":70,"memory":{"used":10,"total":100}}]});
  let body=json!({"machine_id":id,"token":"fixture-metrics","sample":sample});
  let mut invalid=body.clone();invalid["token"]=json!("wrong");
  case.status("POST","/api/machines/client/metrics","",invalid,StatusCode::GONE).await?;
  let mut invalid=body.clone();invalid["sample"]["cpu"]=json!(101);
  case.status("POST","/api/machines/client/metrics","",invalid,StatusCode::BAD_REQUEST).await?;
  for _ in 0..2 {case.status("POST","/api/machines/client/metrics","",body.clone(),StatusCode::OK).await?;}
  ensure!(case.app.collection("machine_metrics_history").count_documents(doc!{"machine_id":machine}).await?==1,"same-minute reports must not grow history");
  let row=case.app.collection("machine_metrics_history").find_one(doc!{"machine_id":machine}).await?.unwrap();
  let ttl=row.get_datetime("expires_at")?.timestamp_millis()-row.get_datetime("at")?.timestamp_millis();ensure!(ttl==7*24*60*60*1000);
  let fleet=case.status("GET","/api/machines/metrics",&cookie,Value::Null,StatusCode::OK).await?;
  ensure!(fleet["machines"][0]["live"]==true && fleet["machines"][0]["reading"]["sample"]["cpu"]==42.5);
  ensure!(!fleet.to_string().contains("fixture-metrics"));
  let foreign=case.status("GET","/api/machines/metrics",&other,Value::Null,StatusCode::OK).await?;ensure!(foreign["machines"].as_array().unwrap().is_empty());
  case.status("GET",&format!("/api/machines/metrics/{id}"),&other,Value::Null,StatusCode::BAD_REQUEST).await?;
  let history=case.status("GET",&format!("/api/machines/metrics/{id}?hours=168"),&cookie,Value::Null,StatusCode::OK).await?;
  ensure!(history["history"].as_array().unwrap().len()==1 && history["latest"]["sample"]["ram"]["used"]==4096);
  case.app.collection("machine_metrics_latest").update_one(doc!{"_id":machine},doc!{"$set":{"at":DateTime::from_millis(DateTime::now().timestamp_millis()-60000)}}).await?;
  let stale=case.status("GET","/api/machines/metrics",&cookie,Value::Null,StatusCode::OK).await?;ensure!(stale["machines"][0]["live"]==false,"stale readings must not masquerade as idle machines");
  Ok(())
 }.await;
    case.db.drop().await?;
    result
}
