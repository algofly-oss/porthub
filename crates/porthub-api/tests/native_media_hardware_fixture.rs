//! Private fixture gateway. Never enrolls in or changes a production deployment.
//! The ignored test requires an owned isolated MongoDB and explicit review gate.
#![cfg(target_os = "linux")]
use anyhow::{ensure, Context, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{path::{Path,PathBuf}, time::Duration};
mod support;
use support::Case;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config { root:PathBuf, source_id:String, desktop_uid:u32, destination_control_port:u16, lifetime_seconds:u64 }
fn valid_source_id(id:&str)->bool {id.len()==70&&id.starts_with("media:")&&id[6..].bytes().all(|b|b.is_ascii_hexdigit())}
fn save(path:&Path,value:&Value)->Result<()> {
    use std::{io::Write,os::unix::fs::OpenOptionsExt};
    let mut file=std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    file.write_all(&serde_json::to_vec(value)?)?;file.sync_all()?;Ok(())
}
fn reports_ready(value:&Value,source:&str,destination:&str,source_id:&str,uid:u32,now:i64)->bool {
    let Some(rows)=value["machines"].as_array() else{return false};
    let find=|id:&str|rows.iter().find(|r|r["id"]==id&&r["enabled"]==true&&r["live"]==true&&r["at"].as_i64().is_some_and(|at|now>=at&&now-at<45000));
    let (Some(src),Some(dst))=(find(source),find(destination)) else{return false};
    let src=&src["report"];let dst=&dst["report"];
    src["protocol"]==1&&src["microphone_enabled"]==true&&dst["protocol"]==1&&dst["receive_enabled"]==true&&dst["receiver_available"]==true&&dst["receiver_identity"]==json!({"vendor":0x1209,"product":1})&&src["sources"].as_array().is_some_and(|rows|rows.iter().any(|row|serde_json::from_value::<porthub_components::media_forward::Source>(row.clone()).ok().is_some_and(|s|s.uid==uid&&s.desktop_session.is_none()&&s.device.id==source_id&&s.device.can_request_capture())))
}
#[tokio::test]
#[ignore="Root-reviewed real native microphone fixture only; isolated DB and explicit exact source required"]
async fn native_authenticated_media_private_gateway()->Result<()> {
    use std::os::unix::fs::MetadataExt;
    ensure!(std::env::var("PORTHUB_NATIVE_MEDIA_FIXTURE_AUTHORIZED").as_deref()==Ok("root-reviewed-microphone-v1"),"Explicit native proof authorization required");
    let spec=PathBuf::from(std::env::var_os("PORTHUB_NATIVE_MEDIA_GATEWAY_SPEC").context("Private gateway specification required")?);
    let meta=std::fs::symlink_metadata(&spec)?;
    ensure!(meta.is_file()&&!meta.file_type().is_symlink()&&meta.uid()==unsafe{libc::geteuid()}&&meta.mode()&0o077==0&&meta.len()<=8192,"Unsafe gateway specification");
    let config:Config=serde_json::from_slice(&std::fs::read(&spec)?)?;
    let root_meta=std::fs::symlink_metadata(&config.root)?;ensure!(root_meta.is_dir()&&!root_meta.file_type().is_symlink()&&root_meta.uid()==unsafe{libc::geteuid()}&&root_meta.mode()&0o077==0,"Unsafe private gateway directory");
    let name=config.root.file_name().and_then(|s|s.to_str()).context("Invalid fixture directory")?;
    ensure!(config.root.parent()==Some(Path::new("/tmp"))&&name.starts_with("porthub-native-media-e2e-")&&name.len()>=48&&name.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-')&&spec.parent()==Some(config.root.as_path()),"Use an isolated native media fixture directory");
    ensure!((1..=180).contains(&config.lifetime_seconds)&&config.desktop_uid>0&&config.destination_control_port>0&&valid_source_id(&config.source_id),"Invalid bounded exact-source fixture configuration");
    let case=Case::new(Default::default()).await?;
    let result:Result<()>=async {
        let (owner,cookie)=case.user("native-media-private-fixture@example.invalid","user").await?;
        let source=ObjectId::new();let destination=ObjectId::new();
        let source_token=uuid::Uuid::new_v4().simple().to_string();let destination_token=uuid::Uuid::new_v4().simple().to_string();
        for (id,token,name) in [(source,&source_token,"Private exact microphone source"),(destination,&destination_token,"Private UAC receiver")] {
            case.app.collection("machines").insert_one(doc!{"_id":id,"user_id":owner,"token":token,"enabled":true,"name":name}).await?;
        }
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let port=listener.local_addr()?.port();
        let router=case.router.clone();let server=tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {axum::serve(listener,router).await}));
        let local=format!("http://127.0.0.1:{port}");let remote=format!("http://127.0.0.1:{}",config.destination_control_port);
        save(&config.root.join("source-profile.json"),&json!({"server":local,"machine_id":source.to_hex(),"token":source_token,"allow_insecure_http_for_tests":true}))?;
        save(&config.root.join("destination-profile.json"),&json!({"server":remote,"machine_id":destination.to_hex(),"token":destination_token,"allow_insecure_http_for_tests":true}))?;
        save(&config.root.join("gateway-ready.json"),&json!({"port":port,"source":source.to_hex(),"destination":destination.to_hex(),"database":case.db.name(),"control_only_ssh_required":true,"capture_started":false}))?;
        let deadline=tokio::time::Instant::now()+Duration::from_secs(config.lifetime_seconds);
        let mut plan:Option<String>=None;let mut revoked=false;let mut ready=false;let mut next_readiness=tokio::time::Instant::now();let mut snapshot=0u32;
        while tokio::time::Instant::now()<deadline&&!config.root.join("stop").exists() {
            if tokio::time::Instant::now()>=next_readiness {
                next_readiness=tokio::time::Instant::now()+Duration::from_millis(500);
                let inventory=case.status("GET","/api/media/inventory",&cookie,Value::Null,StatusCode::OK).await?;
                save(&config.root.join(format!("inventory-{snapshot:03}.json")),&inventory)?;snapshot+=1;
                if !ready&&reports_ready(&inventory,&source.to_hex(),&destination.to_hex(),&config.source_id,config.desktop_uid,mongodb::bson::DateTime::now().timestamp_millis()) {
                    save(&config.root.join("reports-ready.json"),&json!({"source_id":config.source_id,"desktop_uid":config.desktop_uid,"source_ready":true,"receiver_ready":true,"authenticated_owner_inventory":true}))?;ready=true;
                }
            }
            if ready&&plan.is_none()&&config.root.join("activate").exists() {
                let output=case.status("POST","/api/media/forwards",&cookie,json!({"source":source.to_hex(),"destination":destination.to_hex(),"desktop_uid":config.desktop_uid,"source_id":config.source_id,"name":"Private exact-source microphone proof","persistent":false,"identity":{"vendor":0x1209,"product":1}}),StatusCode::OK).await?;
                let id=output["plan"]["id"].as_str().context("Missing authenticated media plan")?.to_owned();
                save(&config.root.join("plan-created.json"),&json!({"id":id,"source_id":config.source_id,"temporary":true,"expires_after_seconds":45}))?;plan=Some(id);
            }
            if !revoked&&config.root.join("revoke").exists(){
                if let Some(id)=&plan {case.status("DELETE",&format!("/api/media/forwards/{id}"),&cookie,Value::Null,StatusCode::OK).await?;revoked=true;save(&config.root.join("plan-revoked.json"),&json!({"id":id,"revoked":true}))?;}
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let final_inventory=case.status("GET","/api/media/inventory",&cookie,Value::Null,StatusCode::OK).await?;save(&config.root.join("inventory-final.json"),&final_inventory)?;
        if !revoked{if let Some(id)=&plan{let _=case.status("DELETE",&format!("/api/media/forwards/{id}"),&cookie,Value::Null,StatusCode::OK).await;}}
        drop(server);Ok(())
    }.await;
    case.db.drop().await?;result
}

#[test]
fn fixture_accepts_real_helper_source_identity_format() {
    let id=porthub_components::media::stable_source_id(porthub_components::media::Kind::Microphone,"linux-pipewire","exact-private-source");
    assert!(valid_source_id(&id));assert!(!valid_source_id(&"a".repeat(64)));assert!(!valid_source_id("media:../../private"));
}

#[test]
fn fixture_readiness_requires_fresh_exact_authorized_reports() {
 use porthub_components::media::{Device,Kind,CaptureState};
 let id=porthub_components::media::stable_source_id(Kind::Microphone,"linux-pipewire","exact");
 let device=Device{id:id.clone(),native_id:id.clone(),name:"Exact".into(),kind:Kind::Microphone,backend:"linux-pipewire".into(),capture_available:false,capture_state:CaptureState::PermissionUnknown,unavailable_reason:None};
 let src=json!({"uid":1000,"desktop_session":null,"device":device});
 let mut value=json!({"machines":[{"id":"source","enabled":true,"live":true,"at":1000,"report":{"protocol":1,"microphone_enabled":true,"sources":[src]}},{"id":"destination","enabled":true,"live":true,"at":1000,"report":{"protocol":1,"receive_enabled":true,"receiver_available":true,"receiver_identity":{"vendor":0x1209,"product":1}}}]});
 assert!(reports_ready(&value,"source","destination",&id,1000,1001));
 assert!(!reports_ready(&value,"source","destination",&id,1001,1001));
 assert!(!reports_ready(&value,"source","destination",&id,1000,46000));
 value["machines"][0]["report"]["sources"][0]["device"]["capture_state"]=json!("denied");
 assert!(!reports_ready(&value,"source","destination",&id,1000,1001));
}
