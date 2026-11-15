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
  let sample=json!({"cpu":42.5,"cores":4,"ram":{"used":4096,"total":8192},"disk":{"used":20,"total":100},"disks":[{"id":"ssd-a","name":"SSD A","used":20,"total":100},{"id":"ssd-b","name":"SSD B","used":50,"total":200}],"gpus":[{"id":"gpu-a","name":"Test GPU","utilization":70,"temperature":65,"fan_speed":40,"memory":{"used":10,"total":100},"integrated":true,"shared_memory":{"used":512,"total":8192},"shared_memory_capacity":8192},{"id":"gpu-b","name":"Test GPU","utilization":20,"temperature":null,"fan_speed":null,"memory":null}]});
  let body=json!({"machine_id":id,"token":"fixture-metrics","sample":sample});
  let mut invalid=body.clone();invalid["token"]=json!("wrong");
  case.status("POST","/api/machines/client/metrics","",invalid,StatusCode::GONE).await?;
  let mut invalid=body.clone();invalid["sample"]["cpu"]=json!(101);
  case.status("POST","/api/machines/client/metrics","",invalid,StatusCode::BAD_REQUEST).await?;
  for _ in 0..2 {case.status("POST","/api/machines/client/metrics","",body.clone(),StatusCode::OK).await?;}
  ensure!(case.app.collection("machine_metrics_history").count_documents(doc!{"machine_id":machine}).await?==1,"same-minute reports must not grow history");
  let row=case.app.collection("machine_metrics_history").find_one(doc!{"machine_id":machine}).await?.unwrap();
  let stored_gpu=row.get_document("sample")?.get_array("gpus")?[0].as_document().unwrap();
  ensure!(!stored_gpu.contains_key("shared_memory")&&!stored_gpu.contains_key("integrated"),"rolling/rollback readers require a legacy-readable stored sample");
  ensure!(row.get_array("gpu_memory_details")?.len()==1,"shared GPU details must be stored atomically beside the legacy sample");
  let ttl=row.get_datetime("expires_at")?.timestamp_millis()-row.get_datetime("at")?.timestamp_millis();ensure!(ttl==7*24*60*60*1000);
  let fleet=case.status("GET","/api/machines/metrics",&cookie,Value::Null,StatusCode::OK).await?;
  ensure!(fleet["machines"][0]["live"]==true && fleet["machines"][0]["reading"]["sample"]["cpu"]==42.5);
  ensure!(!fleet.to_string().contains("fixture-metrics"));
  let foreign=case.status("GET","/api/machines/metrics",&other,Value::Null,StatusCode::OK).await?;ensure!(foreign["machines"].as_array().unwrap().is_empty());
  case.status("GET",&format!("/api/machines/metrics/{id}"),&other,Value::Null,StatusCode::BAD_REQUEST).await?;
  let history=case.status("GET",&format!("/api/machines/metrics/{id}?hours=168"),&cookie,Value::Null,StatusCode::OK).await?;
  ensure!(history["history"].as_array().unwrap().len()==1 && history["latest"]["sample"]["ram"]["used"]==4096);
  let readings=history["history"][0]["sample"].clone();
  ensure!(readings["gpus"].as_array().unwrap().len()==2,"same-name GPUs must retain separate identities");
  let a=readings["gpus"].as_array().unwrap().iter().find(|g|g["id"]=="gpu-a").unwrap();
  let b=readings["gpus"].as_array().unwrap().iter().find(|g|g["id"]=="gpu-b").unwrap();
  ensure!(a["temperature"]==65.0 && a["fan_speed"]==40.0 && b["temperature"].is_null() && b["fan_speed"].is_null());
  ensure!(a["integrated"]==true && a["shared_memory"]["used"]==512 && a["shared_memory_capacity"]==8192,"shared memory must survive owner-scoped history aggregation");
  ensure!(b.get("shared_memory").is_none(),"shared memory must not leak to a different GPU");
  ensure!(history["latest"]["sample"]["gpus"][0]["shared_memory"]["used"]==512,"latest must restore shared memory details");
  ensure!(readings["disks"].as_array().unwrap().len()==2,"per-drive readings must survive history aggregation");
  case.app.collection("machine_metrics_latest").update_one(doc!{"_id":machine},doc!{"$set":{"at":DateTime::from_millis(DateTime::now().timestamp_millis()-60000)}}).await?;
  let stale=case.status("GET","/api/machines/metrics",&cookie,Value::Null,StatusCode::OK).await?;ensure!(stale["machines"][0]["live"]==false,"stale readings must not masquerade as idle machines");
  Ok(())
 }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn physical_drive_health_is_deduplicated_owner_scoped_and_retains_removed_drives(
) -> Result<()> {
    let case = Case::new(Default::default()).await?;
    let result:Result<()>=async {
  let(owner,cookie)=case.user("drive-health-owner@example.invalid","user").await?;
  let(_,foreign)=case.user("drive-health-other@example.invalid","user").await?;
  let machine=ObjectId::new();let id=machine.to_hex();
  case.app.collection("machines").insert_one(doc!{"_id":machine,"name":"Drive fixture","token":"drive-fixture-secret","user_id":owner,"enabled":true}).await?;
  let observed=DateTime::now().timestamp_millis();
  let drive=json!({"id":"a".repeat(64),"name":"Fixture SSD","protocol":"nvme","capacity":1_000_000,"present":true,"status":"healthy","observed_at":observed,"checked_at":observed,"temperature":35,"percentage_used":3,"available_spare":100,"spare_threshold":10,"power_on_hours":30,"power_cycles":2,"unsafe_shutdowns":0,"media_errors":0,"reallocated_sectors":null,"pending_sectors":null,"uncorrectable_sectors":null,"short_test_supported":true,"self_test":"passed","last_test_started":null,"next_test_at":null,"reasons":[]});
  let mut body=json!({"machine_id":id,"token":"drive-fixture-secret","sample":{"cpu":10,"cores":4,"ram":{"used":1,"total":4},"disk":{"used":10,"total":100},"gpus":[],"drive_health":[drive]}});
  let mut invalid=body.clone();invalid["sample"]["drive_health"][0]["present"]=json!(false);
  case.status("POST","/api/machines/client/metrics","",invalid,StatusCode::BAD_REQUEST).await?;
  for _ in 0..2 {case.status("POST","/api/machines/client/metrics","",body.clone(),StatusCode::OK).await?;}
  ensure!(case.app.collection("machine_drive_health_history").count_documents(doc!{"machine_id":machine}).await?==1,"cached SMART observations must not duplicate per metrics upload");
  let minute=case.app.collection("machine_metrics_history").find_one(doc!{"machine_id":machine}).await?.unwrap();ensure!(!minute.get_document("sample")?.contains_key("drive_health"),"SMART history must not be copied into minute utilization buckets");
  body["sample"]["drive_health"][0]["observed_at"]=json!(observed+1);body["sample"]["drive_health"][0]["checked_at"]=json!(observed+1);body["sample"]["drive_health"][0]["status"]=json!("warning");body["sample"]["drive_health"][0]["media_errors"]=json!(1);body["sample"]["drive_health"][0]["reasons"]=json!(["Media or data-integrity errors recorded"]);
  case.status("POST","/api/machines/client/metrics","",body.clone(),StatusCode::OK).await?;
  body["sample"]["drive_health"][0]["observed_at"]=json!(observed+2);body["sample"]["drive_health"][0]["present"]=json!(false);body["sample"]["drive_health"][0]["status"]=json!("removed");body["sample"]["drive_health"][0]["reasons"]=json!(["Drive removed from this machine"]);
  case.status("POST","/api/machines/client/metrics","",body,StatusCode::OK).await?;
  let route=format!("/api/machines/metrics/{id}/drives?days=999");
  case.status("GET",&route,&foreign,Value::Null,StatusCode::BAD_REQUEST).await?;
  let output=case.status("GET",&route,&cookie,Value::Null,StatusCode::OK).await?;
  ensure!(output["retention_days"]==90&&output["days"]==90);
  ensure!(output["history"].as_array().unwrap().len()==3&&output["drives"][0]["status"]=="removed");
  ensure!(output["history"].as_array().unwrap().iter().any(|p|p["snapshot"]["status"]=="warning"));
  ensure!(!output.to_string().contains("drive-fixture-secret"));
  let retained=case.app.collection("machine_drive_health_history").find_one(doc!{"machine_id":machine}).await?.unwrap();ensure!(retained.get_datetime("expires_at")?.timestamp_millis()-retained.get_datetime("at")?.timestamp_millis()==90*24*60*60*1000);
  Ok(())
 }.await;
    case.db.drop().await?;
    result
}
