use anyhow::{ensure, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use porthub_api::{config::Config, firewall_history, App};
use serde_json::{json, Value};
mod support;
use support::Case;
#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn hover_is_owner_scoped_interval_aware_and_honest_about_sources_and_configuration(
) -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result=async {
        let (owner,cookie)=case.user("hover-owner@example.invalid","user").await?;
        let (foreign,foreign_cookie)=case.user("hover-foreign@example.invalid","user").await?;
        let now=DateTime::now().timestamp_millis()/1000;
        let at=now-20;
        let machine=ObjectId::new();
        case.app.collection("machines").insert_one(doc!{"_id":machine,"user_id":owner,"name":"Actual machine"}).await?;
        firewall_history::initialize(&case.app).await?;
        let mut ids=Vec::new();
        for n in 0..9 {
            let id=ObjectId::new();ids.push(id);
            let record=doc!{"_id":id,"user_id":owner,"machine_id":machine,"service_name":format!("Service {n}"),"internal_ip":"https://person:secret@example.com/private?token=hidden","internal_port":3000,"external_port":8000+n,"created_at":DateTime::from_millis((now-7200)*1000)};
            case.app.collection("connections").insert_one(record.clone()).await?;
            let mut sample=json!({"timestamp":at,"interval_seconds":5,"in_rate":100+n,"out_rate":2,"in_bytes":500,"incoming_ips":["198.51.100.99"]});
            if n!=7 {
                sample["accepted_incoming_ips"]=if n==6 {json!([])}else{json!(["192.0.2.10","2001:db8::1"])};
                sample["accepted_incoming_ips_window_seconds"]=json!(if n==8 {2}else{5});
                sample["accepted_incoming_ips_address_families"]=json!(["ipv4","ipv6"]);
            }
            firewall_history::persist(&case.app,&record,&[sample]).await?;
        }
        // Legacy persisted samples lack a trustworthy recorded port snapshot.
        case.app.collection(firewall_history::COLLECTION).update_many(doc!{"connection_id":ids[4]},doc!{"$unset":{"public_port":""}}).await?;
        let foreign_id=ObjectId::new();
        let foreign_record=doc!{"_id":foreign_id,"user_id":foreign,"external_port":9999,"created_at":DateTime::from_millis((now-7200)*1000)};
        case.app.collection("connections").insert_one(foreign_record.clone()).await?;
        firewall_history::persist(&case.app,&foreign_record,&[json!({"timestamp":at,"in_rate":999999,"incoming_ips":["203.0.113.99"]})]).await?;
        let path=format!("/api/traffic/hover?timestamp={}&limit=6",at-3);
        let (status,headers,page)=case.call("GET",&path,&cookie,Value::Null,&[]).await?;
        ensure!(status==StatusCode::OK,"{page}");
        ensure!(headers["cache-control"]=="private, no-store");
        ensure!(page["total_contributors"]==9&&page["truncated"]==true);
        let rows=page["contributors"].as_array().unwrap();
        ensure!(rows.len()==6&&rows[0]["connection_id"]==ids[8].to_hex());
        ensure!(rows[0]["source_status"]=="outside_observation_window"&&rows[0]["accepted_incoming_ips"].is_null());
        ensure!(rows[1]["source_status"]=="unavailable"&&rows[1]["accepted_incoming_ips"].is_null(),"Legacy attempts must never become accepted observations");
        ensure!(rows[2]["accepted_incoming_ips"]==json!([]),"Measured empty differs from unknown");
        ensure!(rows[3]["accepted_incoming_ips"]==json!(["192.0.2.10","2001:db8::1"]));
        ensure!(rows[0]["measurement"]["end_timestamp"]==at&&rows[0]["measurement"]["start_timestamp"].as_f64()==Some((at-5)as f64));
        ensure!(rows[0]["machine_name"]=="Actual machine");
        ensure!(rows[0]["public_port"]==8008&&rows[0]["public_port_scope"]=="recorded_measurement");
        ensure!(rows[0]["configured_target"]["host"]=="example.com");
        ensure!(rows[4]["public_port"].is_null()&&rows[4]["public_port_scope"]=="unavailable");
        ensure!(!page.to_string().contains("secret")&&!page.to_string().contains("hidden")&&!page.to_string().contains("203.0.113.99"));
        // Configuration changes do not relabel the historical observed port.
        case.app.collection("connections").update_one(doc!{"_id":ids[8]},doc!{"$set":{"external_port":9000,"internal_ip":"192.0.2.44","internal_port":44}}).await?;
        let changed=case.status("GET",&path,&cookie,Value::Null,StatusCode::OK).await?;
        ensure!(changed["contributors"][0]["public_port"]==8008);
        ensure!(changed["contributors"][0]["configured_target"]==json!({"host":"192.0.2.44","port":44,"scope":"current_configuration"}));
        // Cached data must not survive current ownership removal/reassignment.
        case.app.collection("connections").update_one(doc!{"_id":ids[8]},doc!{"$set":{"user_id":foreign}}).await?;
        let removed=case.status("GET",&path,&cookie,Value::Null,StatusCode::OK).await?;
        ensure!(!removed["contributors"].as_array().unwrap().iter().any(|r|r["connection_id"]==ids[8].to_hex()));
        let foreign_page=case.status("GET",&path,&foreign_cookie,Value::Null,StatusCode::OK).await?;
        ensure!(foreign_page["contributors"].as_array().unwrap().iter().all(|r|r["connection_id"]!=ids[0].to_hex()));
        ensure!(foreign_page["contributors"].as_array().unwrap().iter().find(|r|r["connection_id"]==ids[8].to_hex()).is_none(),"Prior owner's traffic must not transfer with reassigned connection");
        case.status("GET",&format!("/api/traffic/hover?timestamp={}&limit=11",at),&cookie,Value::Null,StatusCode::BAD_REQUEST).await?;
        case.status("GET",&format!("/api/traffic/hover?timestamp={}",now-3601),&cookie,Value::Null,StatusCode::BAD_REQUEST).await?;
        // Missing recorded metadata (older persisted rows) stays unknown.
        let fresh=App::new(Config::default(),case.db.clone());
        ensure!(!firewall_history::read(&fresh,&mongodb::bson::Bson::ObjectId(owner),&[ids[3]]).await?[&ids[3].to_hex()][0]["accepted_incoming_ips"].is_null());
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn hover_reads_one_point_without_waiting_for_fleet_history() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result = async {
        let (owner, cookie) = case.user("point-hover@example.invalid", "user").await?;
        firewall_history::initialize(&case.app).await?;
        let now = DateTime::now().timestamp_millis() / 1000;
        let machine = ObjectId::new();
        case.app.collection("machines").insert_one(doc! {"_id":machine,"user_id":owner,"name":"Point fixture"}).await?;
        let ips = (1..=128).map(|n| format!("192.0.2.{n}")).collect::<Vec<_>>();
        let mut first = None;
        for n in 0..32 {
            let id = ObjectId::new();
            let record = doc! {"_id":id,"user_id":owner,"machine_id":machine,"service_name":format!("Port {n}"),"internal_ip":"192.0.2.200","internal_port":3000,"external_port":8000+n,"created_at":DateTime::from_millis((now-7200)*1000)};
            case.app.collection("connections").insert_one(record.clone()).await?;
            let samples = (1..=120).map(|step| json!({"timestamp":now-3600+step*30,"interval_seconds":30,"in_rate":n+1,"out_rate":0,"in_bytes":30*(n+1),"accepted_incoming_ips":ips,"accepted_incoming_ips_window_seconds":30,"accepted_incoming_ips_address_families":["ipv4"]})).collect::<Vec<_>>();
            firewall_history::persist(&case.app, &record, &samples).await?;
            if n == 0 { first = Some((id, record)); }
        }
        let (first_id, first_record) = first.unwrap();
        // The first covering endpoint is authoritative even when it is zero.
        // A later overlapping positive endpoint must not manufacture activity.
        firewall_history::persist(&case.app, &first_record, &[
            json!({"timestamp":now-150,"interval_seconds":30,"in_rate":0,"out_rate":0}),
            json!({"timestamp":now-120,"interval_seconds":90,"in_rate":99999,"out_rate":0}),
        ]).await?;
        let baseline = App::new(Config::default(), case.db.clone());
        let started = std::time::Instant::now();
        let full = porthub_api::inventory_traffic::snapshot(&baseline, &mongodb::bson::Bson::ObjectId(owner)).await?;
        let full_ms = started.elapsed().as_millis();
        ensure!(full.ports.len() == 32);
        // A busy fleet read model cannot hold a point inspection hostage.
        let fleet_guard = case.app.inventory_traffic.0.lock().await;
        let started = std::time::Instant::now();
        let answer = tokio::time::timeout(std::time::Duration::from_secs(2), case.call("GET", &format!("/api/traffic/hover?timestamp={}&limit=6", now-177), &cookie, Value::Null, &[])).await;
        let point_ms = started.elapsed().as_millis();
        drop(fleet_guard);
        let (status, _, page) = answer??;
        ensure!(status == StatusCode::OK, "{page}");
        ensure!(page["total_contributors"] == 31 && page["truncated"] == true, "{page}");
        let rows = page["contributors"].as_array().unwrap();
        ensure!(rows.len() == 6 && rows[0]["incoming_bytes_per_second"].as_f64() == Some(32.));
        ensure!(rows.iter().all(|row| row["connection_id"] != first_id.to_hex()));
        ensure!(rows.iter().all(|row| row["measurement"]["end_timestamp"] == now-150));
        ensure!(rows[0]["accepted_incoming_ips"].as_array().unwrap().len() == 16 && rows[0]["source_ips_truncated"] == true);
        println!("POINT_HOVER_BENCHMARK connections=32 retained_measurements=3840 full_history_ms={full_ms} point_ms={point_ms} fleet_cache_locked=true response_rows=6");
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}
