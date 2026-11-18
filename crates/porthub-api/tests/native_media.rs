use anyhow::{ensure,Context,Result};
use axum::http::StatusCode;
use futures_util::{SinkExt,StreamExt};
use mongodb::bson::{self,doc,oid::ObjectId,DateTime};
use serde_json::json;
use tokio_tungstenite::tungstenite::{client::IntoClientRequest,Message};
mod support;
use support::Case;
#[tokio::test]
#[ignore="requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn native_media_plans_bind_owner_source_desktop_receiver_and_revoke_streams()->Result<()> {
 let case=Case::new(Default::default()).await?;
 let result:Result<()>=async {
 let(owner,cookie)=case.user("media-owner@example.invalid","user").await?;
 let(other,other_cookie)=case.user("media-other@example.invalid","user").await?;
 let a=ObjectId::new();let b=ObjectId::new();let c=ObjectId::new();
 for(id,user,token)in[(a,owner,"a-token"),(b,owner,"b-token"),(c,other,"c-token")] {case.app.collection("machines").insert_one(doc!{"_id":id,"user_id":user,"enabled":true,"token":token,"name":"Media fixture"}).await?;}
 let source_id=format!("media:{}","a".repeat(64));
 let source=json!({"uid":1000,"device":{"id":source_id,"name":"Exact microphone","kind":"microphone","backend":"test-explicit","native_id":"exact-endpoint","capture_available":false,"capture_state":"permission-unknown","unavailable_reason":null}});
 let principal=format!("windows:{}","b".repeat(64));let windows_id=format!("media:{}","c".repeat(64));
 let windows_source=json!({"uid":0,"desktop_session":principal,"device":{"id":windows_id,"name":"Exact Windows microphone","kind":"microphone","backend":"windows-wasapi","native_id":"explicit-wasapi-endpoint","capture_available":false,"capture_state":"permission-unknown","unavailable_reason":null}});
 for(id,token,sources)in[(a,"a-token",json!([source.clone(),windows_source.clone()])),(b,"b-token",json!([])),(c,"c-token",json!([]))] {case.status("POST","/api/media/client/report","",json!({"machine_id":id.to_hex(),"token":token,"protocol":1,"usb_enabled":false,"microphone_enabled":true,"receive_enabled":true,"receiver_available":true,"receiver_identity":{"vendor":0x1209,"product":1},"receiver_unavailable_reason":null,"sources":sources,"states":[]}),StatusCode::OK).await?;}
 let create=json!({"source":a.to_hex(),"destination":b.to_hex(),"desktop_uid":1000,"source_id":source_id,"name":"Private fixture microphone","identity":{"vendor":0x1209,"product":1},"persistent":true});
 let mut foreign=create.clone();foreign["destination"]=c.to_hex().into();case.status("POST","/api/media/forwards",&cookie,foreign,StatusCode::CONFLICT).await?;
 let mut wrong_uid=create.clone();wrong_uid["desktop_uid"]=1001.into();case.status("POST","/api/media/forwards",&cookie,wrong_uid,StatusCode::CONFLICT).await?;
 let mut wrong_identity=create.clone();wrong_identity["identity"]["product"]=2.into();case.status("POST","/api/media/forwards",&cookie,wrong_identity,StatusCode::CONFLICT).await?;
 let mut windows=create.clone();windows["desktop_uid"]=0.into();windows["source_id"]=windows_id.clone().into();windows["desktop_session"]=format!("windows:{}","d".repeat(64)).into();
 case.status("POST","/api/media/forwards",&cookie,windows.clone(),StatusCode::CONFLICT).await?;
 windows["desktop_session"]=principal.into();windows.as_object_mut().unwrap().remove("identity");
 let win=case.status("POST","/api/media/forwards",&cookie,windows,StatusCode::OK).await?;ensure!(win["plan"]["identity"]["vendor"]==0x1209&&win["plan"]["desktop_uid"]==0);
 case.status("POST",&format!("/api/media/machines/{}/discover",a.to_hex()),&other_cookie,json!({}),StatusCode::CONFLICT).await?;
 case.status("POST",&format!("/api/media/machines/{}/discover",a.to_hex()),&cookie,json!({}),StatusCode::OK).await?;
 let refresh=json!({"machine_id":a.to_hex(),"token":"a-token","protocol":1,"usb_enabled":false,"microphone_enabled":true,"receive_enabled":true,"receiver_available":true,"receiver_identity":{"vendor":0x1209,"product":1},"receiver_unavailable_reason":null,"sources":[source,windows_source],"states":[]});
 let discovery=case.status("POST","/api/media/client/report","",refresh.clone(),StatusCode::OK).await?;ensure!(discovery["discover"]==true);
 let once=case.status("POST","/api/media/client/report","",refresh,StatusCode::OK).await?;ensure!(once["discover"]==false);
 let made=case.status("POST","/api/media/forwards",&cookie,create.clone(),StatusCode::OK).await?;let id=made["plan"]["id"].as_str().unwrap().to_owned();
 let hidden=case.status("GET","/api/media/forwards",&other_cookie,json!({}),StatusCode::OK).await?;ensure!(hidden["plans"].as_array().unwrap().is_empty());
 // A different owner's deletion is harmless, and a different endpoint cannot
 // renew or stop the source's plan even when its owner is otherwise the same.
 case.status("DELETE",&format!("/api/media/forwards/{id}"),&other_cookie,json!({}),StatusCode::OK).await?;
 case.status("POST","/api/media/client/action","",json!({"machine_id":b.to_hex(),"token":"b-token","action":"stop","id":id}),StatusCode::CONFLICT).await?;
 for(collection,filter,field,bad,good)in [
  ("native_media_inventory",doc!{"_id":a},"microphone_enabled",bson::Bson::Boolean(false),bson::Bson::Boolean(true)),
  ("native_media_inventory",doc!{"_id":b},"receive_enabled",bson::Bson::Boolean(false),bson::Bson::Boolean(true)),
  ("machines",doc!{"_id":a},"enabled",bson::Bson::Boolean(false),bson::Bson::Boolean(true)),
  ("machines",doc!{"_id":b},"deletion_pending",bson::Bson::Boolean(true),bson::Bson::Boolean(false)),
 ] {
  case.app.collection(collection).update_one(filter.clone(),doc!{"$set":{field:bad}}).await?;
  case.status("POST","/api/media/forwards",&cookie,create.clone(),StatusCode::CONFLICT).await?;
  case.app.collection(collection).update_one(filter,doc!{"$set":{field:good}}).await?;
 }
 case.app.collection("native_media_inventory").update_one(doc!{"_id":a},doc!{"$set":{"at":DateTime::from_millis(1)}}).await?;
 case.status("POST","/api/media/forwards",&cookie,create,StatusCode::CONFLICT).await?;
 case.app.collection("native_media_inventory").update_one(doc!{"_id":a},doc!{"$set":{"at":DateTime::now()}}).await?;
 let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let addr=listener.local_addr()?;let router=case.router.clone();let _server=tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move{axum::serve(listener,router).await}));
 let request=|machine:ObjectId,token:&str,side:&str|->Result<_>{let mut r=format!("ws://{addr}/api/media/stream/{id}/{side}").into_client_request()?;r.headers_mut().insert("x-porthub-machine-id",machine.to_hex().parse()?);r.headers_mut().insert("authorization",format!("Bearer {token}").parse()?);Ok(r)};
 ensure!(tokio_tungstenite::connect_async(request(b,"b-token","source")?).await.is_err());
 ensure!(tokio_tungstenite::connect_async(request(c,"c-token","destination")?).await.is_err());
 let(mut source,_)=tokio_tungstenite::connect_async(request(a,"a-token","source")?).await?;
 let(mut destination,_)=tokio_tungstenite::connect_async(request(b,"b-token","destination")?).await?;
 ensure!(source.next().await.unwrap()?.into_text()?=="ready");ensure!(destination.next().await.unwrap()?.into_text()?=="ready");
 source.send(Message::Binary(vec![0,1,2,3].into())).await?;
 loop {match destination.next().await.unwrap()?{Message::Binary(bytes)=>{ensure!(bytes.as_ref()==[0,1,2,3]);break;},Message::Ping(bytes)=>destination.send(Message::Pong(bytes)).await?,_=>{}}}
 case.app.collection("native_media_inventory").update_one(doc!{"_id":a},doc!{"$set":{"microphone_enabled":false}}).await?;
 tokio::time::timeout(std::time::Duration::from_secs(7),async {loop {match destination.next().await{None|Some(Err(_))|Some(Ok(Message::Close(_)))=>break,Some(Ok(Message::Ping(bytes)))=>destination.send(Message::Pong(bytes)).await?,_=>{}}}Ok::<_,anyhow::Error>(())}).await??;
 // Fill a real peer's TCP receive window and prove cancellation remains
 // independent of the stalled forwarding write. These sockets contain only
 // synthetic bytes; no device or microphone is involved.
 case.app.collection("native_media_inventory").update_one(doc!{"_id":a},doc!{"$set":{"microphone_enabled":true}}).await?;
 let(mut stalled_source,_)=tokio_tungstenite::connect_async(request(a,"a-token","source")?).await?;
 let(mut stalled_destination,_)=tokio_tungstenite::connect_async(request(b,"b-token","destination")?).await?;
 ensure!(stalled_source.next().await.unwrap()?.into_text()?=="ready");ensure!(stalled_destination.next().await.unwrap()?.into_text()?=="ready");
 #[cfg(target_os="linux")]
 {use std::os::fd::AsRawFd;if let tokio_tungstenite::MaybeTlsStream::Plain(tcp)=stalled_destination.get_ref(){let size=1024i32;ensure!(unsafe{libc::setsockopt(tcp.as_raw_fd(),libc::SOL_SOCKET,libc::SO_RCVBUF,(&size as *const i32).cast(),std::mem::size_of::<i32>() as libc::socklen_t)}==0);}}
 let(blocked,confirmed)=tokio::sync::oneshot::channel();
 let _flood=tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move{
  let mut blocked=Some(blocked);let payload=Message::Binary(vec![7;262144].into());
  for _ in 0..512 {
   let send=stalled_source.send(payload.clone());tokio::pin!(send);
   tokio::select!{biased;result=&mut send=>result?,_=tokio::time::sleep(std::time::Duration::from_millis(300))=>{let _=blocked.take().unwrap().send(());let _=send.await;return Ok::<_,anyhow::Error>(());}}
  }
  anyhow::bail!("Fixture did not produce actual write backpressure")
 }));
 tokio::time::timeout(std::time::Duration::from_secs(5),confirmed).await??;
 case.app.collection("native_media_inventory").update_one(doc!{"_id":a},doc!{"$set":{"microphone_enabled":false}}).await?;
 tokio::time::sleep(std::time::Duration::from_secs(4)).await;
 case.app.collection("native_media_inventory").update_one(doc!{"_id":a},doc!{"$set":{"microphone_enabled":true}}).await?;
 // The unread old destination stays open. Only independent authorization can
 // release the active registry slot; a new pair must therefore become ready.
 let(mut renewed_source,_)=tokio_tungstenite::connect_async(request(a,"a-token","source")?).await?;
 let(mut renewed_destination,_)=tokio_tungstenite::connect_async(request(b,"b-token","destination")?).await?;
 tokio::time::timeout(std::time::Duration::from_secs(3),async{ensure!(renewed_source.next().await.context("Source pair closed")??.into_text()?=="ready");ensure!(renewed_destination.next().await.context("Destination pair closed")??.into_text()?=="ready");Ok::<_,anyhow::Error>(())}).await??;
 drop(stalled_destination);drop(_flood);drop(renewed_source);drop(renewed_destination);
 Ok(())
 }.await;
 case.db.drop().await?;result
}

#[tokio::test]
#[ignore="requires isolated MongoDB and real read-only helper DTO via PORTHUB_TEST_MEDIA_INVENTORY_DTO"]
async fn real_readonly_helper_inventory_allows_explicit_unknown_permission_but_never_denied_or_camera()->Result<()> {
 use porthub_components::media::{Device,Kind,CaptureState};
 let path=std::env::var("PORTHUB_TEST_MEDIA_INVENTORY_DTO")?;
 let inventory:Vec<Device>=serde_json::from_slice(&std::fs::read(path)?)?;
 let device=inventory.into_iter().find(|d|d.kind==Kind::Microphone&&d.capture_state==CaptureState::PermissionUnknown).ok_or_else(||anyhow::anyhow!("Real helper has no supported permission-unknown microphone"))?;
 ensure!(!device.capture_available&&device.valid()&&device.can_request_capture());
 let case=Case::new(Default::default()).await?;
 let result:Result<()>=async {
  let(owner,cookie)=case.user("real-media-inventory@example.invalid","user").await?;let source=ObjectId::new();let destination=ObjectId::new();
  for(id,token)in[(source,"source"),(destination,"destination")]{case.app.collection("machines").insert_one(doc!{"_id":id,"user_id":owner,"enabled":true,"token":token,"name":"Private readonly DTO fixture"}).await?;}
  let report=|id:ObjectId,token:&str,sources:serde_json::Value|json!({"machine_id":id.to_hex(),"token":token,"protocol":1,"usb_enabled":false,"microphone_enabled":true,"receive_enabled":true,"receiver_available":true,"receiver_identity":{"vendor":0x1209,"product":1},"receiver_unavailable_reason":null,"sources":sources,"states":[]});
  case.status("POST","/api/media/client/report","",report(source,"source",json!([{"uid":1000,"device":device}])),StatusCode::OK).await?;
  case.status("POST","/api/media/client/report","",report(destination,"destination",json!([])),StatusCode::OK).await?;
  let create=json!({"source":source.to_hex(),"destination":destination.to_hex(),"desktop_uid":1000,"source_id":device.id,"name":"Readonly DTO authorization test; no capture worker","persistent":true});
  case.status("POST","/api/media/forwards",&cookie,create.clone(),StatusCode::OK).await?;
  for state in [CaptureState::Denied,CaptureState::Unsupported]{let mut denied=device.clone();denied.capture_state=state;denied.capture_available=false;case.status("POST","/api/media/client/report","",report(source,"source",json!([{"uid":1000,"device":denied}])),StatusCode::OK).await?;case.status("POST","/api/media/forwards",&cookie,create.clone(),StatusCode::CONFLICT).await?;}
  let mut camera=device.clone();camera.kind=Kind::Camera;camera.capture_state=CaptureState::Unsupported;camera.capture_available=false;
  case.status("POST","/api/media/client/report","",report(source,"source",json!([{"uid":1000,"device":camera}])),StatusCode::OK).await?;case.status("POST","/api/media/forwards",&cookie,create,StatusCode::CONFLICT).await?;
  Ok(())
 }.await;
 case.db.drop().await?;result
}

#[tokio::test]
#[ignore="requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn camera_plans_require_negotiated_kind_and_independent_client_permissions()->Result<()> {
 use porthub_components::media::{Kind,stable_source_id};
 let case=Case::new(Default::default()).await?;
 let result:Result<()>=async{
  let(owner,cookie)=case.user("camera-owner@example.invalid","user").await?;let(other,_)=case.user("camera-other@example.invalid","user").await?;
  let a=ObjectId::new();let b=ObjectId::new();let foreign=ObjectId::new();
  for(id,user,token)in[(a,owner,"camera-a"),(b,owner,"camera-b"),(foreign,other,"camera-foreign")]{case.app.collection("machines").insert_one(doc!{"_id":id,"user_id":user,"enabled":true,"token":token}).await?;}
  let source_id=stable_source_id(Kind::Camera,"v4l2","explicit-fixture-camera");
  let source=json!({"uid":1000,"desktop_session":null,"device":{"id":source_id,"native_id":source_id,"name":"Explicit camera fixture","kind":"camera","backend":"v4l2","capture_available":false,"capture_state":"permission-unknown","unavailable_reason":null}});
  let report=|id:ObjectId,token:&str,sources:serde_json::Value|json!({"machine_id":id.to_hex(),"token":token,"protocol":2,"usb_enabled":false,"microphone_enabled":true,"camera_enabled":true,"receive_enabled":true,"receiver_available":false,"camera_receiver_available":true,"receiver_identity":{"vendor":0x1209,"product":1},"receiver_unavailable_reason":null,"camera_receiver_unavailable_reason":null,"sources":sources,"states":[]});
  let source_report=report(a,"camera-a",json!([source]));let destination_report=report(b,"camera-b",json!([]));
  case.status("POST","/api/media/client/report","",source_report.clone(),StatusCode::OK).await?;case.status("POST","/api/media/client/report","",destination_report.clone(),StatusCode::OK).await?;
  let create=json!({"source":a.to_hex(),"destination":b.to_hex(),"desktop_uid":1000,"source_id":source_id,"name":"Camera fixture","mode":"phv1-camera-mjpeg-v1","persistent":true});
  let mut mic=create.clone();mic["mode"]=json!("phm1-microphone-v1");case.status("POST","/api/media/forwards",&cookie,mic,StatusCode::CONFLICT).await?;
  let mut foreign_request=create.clone();foreign_request["destination"]=json!(foreign.to_hex());case.status("POST","/api/media/forwards",&cookie,foreign_request,StatusCode::CONFLICT).await?;
  let created=case.status("POST","/api/media/forwards",&cookie,create.clone(),StatusCode::OK).await?;ensure!(created["plan"]["mode"]=="phv1-camera-mjpeg-v1");
  // Turning off microphone/raw USB sharing cannot disable authorized cameras.
  let mut camera_only=source_report.clone();camera_only["microphone_enabled"]=json!(false);case.status("POST","/api/media/client/report","",camera_only.clone(),StatusCode::OK).await?;case.status("POST","/api/media/forwards",&cookie,create.clone(),StatusCode::OK).await?;
  for (machine,field)in[(a,"camera_enabled"),(b,"receive_enabled"),(b,"camera_receiver_available")] {case.app.collection("native_media_inventory").update_one(doc!{"_id":machine},doc!{"$set":{field:false}}).await?;case.status("POST","/api/media/forwards",&cookie,create.clone(),StatusCode::CONFLICT).await?;case.app.collection("native_media_inventory").update_one(doc!{"_id":machine},doc!{"$set":{field:true}}).await?;}
  let mut denied=camera_only.clone();denied["sources"][0]["device"]["capture_state"]=json!("denied");case.status("POST","/api/media/client/report","",denied,StatusCode::OK).await?;case.status("POST","/api/media/forwards",&cookie,create.clone(),StatusCode::CONFLICT).await?;
  case.status("POST","/api/media/client/report","",camera_only,StatusCode::OK).await?;
  let mut old=destination_report;old["protocol"]=json!(1);old.as_object_mut().unwrap().remove("camera_enabled");old.as_object_mut().unwrap().remove("camera_receiver_available");old.as_object_mut().unwrap().remove("camera_receiver_unavailable_reason");case.status("POST","/api/media/client/report","",old,StatusCode::OK).await?;case.status("POST","/api/media/forwards",&cookie,create,StatusCode::CONFLICT).await?;
  Ok(())
 }.await;case.db.drop().await?;result
}

#[tokio::test]
#[ignore="requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn speaker_plans_capture_selected_source_and_render_destination_without_usb_identity()->Result<()> {
 let case=Case::new(Default::default()).await?;
 let result:Result<()>=async {
 let(owner,cookie)=case.user("speaker-owner@example.invalid","user").await?;
 let(other,other_cookie)=case.user("speaker-other@example.invalid","user").await?;
 let a=ObjectId::new();let b=ObjectId::new();let c=ObjectId::new();
 for(id,user,token)in[(a,owner,"speaker-a"),(b,owner,"speaker-b"),(c,other,"speaker-c")] {case.app.collection("machines").insert_one(doc!{"_id":id,"user_id":user,"enabled":true,"token":token,"name":"Speaker fixture"}).await?;}
 let source_id=format!("media:{}","e".repeat(64));
 let source=json!({"uid":1000,"device":{"id":source_id,"name":"Selected source output","kind":"speaker","backend":"test-explicit","native_id":"local-only-output","capture_available":true,"capture_state":"ready","unavailable_reason":null}});
 for(id,token,sources)in[(a,"speaker-a",json!([source])),(b,"speaker-b",json!([])),(c,"speaker-c",json!([]))] {
 case.status("POST","/api/media/client/report","",json!({"machine_id":id.to_hex(),"token":token,"protocol":2,"usb_enabled":false,"microphone_enabled":false,"camera_enabled":false,"speaker_enabled":true,"speaker_receiver_available":true,"speaker_unavailable_reason":null,"receive_enabled":true,"receiver_available":false,"receiver_identity":null,"receiver_unavailable_reason":"No USB receiver configured","sources":sources,"states":[]}),StatusCode::OK).await?;
 }
 let create=json!({"source":a.to_hex(),"destination":b.to_hex(),"desktop_uid":1000,"source_id":source_id,"name":"Source playback to destination speaker","persistent":true,"mode":"phs1-speaker-v1"});
 case.status("POST","/api/media/forwards",&other_cookie,create.clone(),StatusCode::CONFLICT).await?;
 let mut foreign=create.clone();foreign["destination"]=c.to_hex().into();case.status("POST","/api/media/forwards",&cookie,foreign,StatusCode::CONFLICT).await?;
 let mut wrong=create.clone();wrong["desktop_uid"]=1001.into();case.status("POST","/api/media/forwards",&cookie,wrong,StatusCode::CONFLICT).await?;
 let made=case.status("POST","/api/media/forwards",&cookie,create,StatusCode::OK).await?;
 ensure!(made["plan"]["source"]==a.to_hex()&&made["plan"]["destination"]==b.to_hex()&&made["plan"]["mode"]=="phs1-speaker-v1");
 let id=made["plan"]["id"].as_str().context("Missing speaker plan")?;
 let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let addr=listener.local_addr()?;let router=case.router.clone();let _server=tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move{axum::serve(listener,router).await}));
 let request=|machine:ObjectId,token:&str,side:&str|->Result<_>{let mut r=format!("ws://{addr}/api/media/stream/{id}/{side}").into_client_request()?;r.headers_mut().insert("x-porthub-machine-id",machine.to_hex().parse()?);r.headers_mut().insert("authorization",format!("Bearer {token}").parse()?);Ok(r)};
 ensure!(tokio_tungstenite::connect_async(request(b,"speaker-b","source")?).await.is_err());
 let(mut producer,_)=tokio_tungstenite::connect_async(request(a,"speaker-a","source")?).await?;
 let(mut renderer,_)=tokio_tungstenite::connect_async(request(b,"speaker-b","destination")?).await?;
 ensure!(producer.next().await.context("No source ready")??.into_text()?=="ready");ensure!(renderer.next().await.context("No destination ready")??.into_text()?=="ready");
 let samples=0.25f32.to_le_bytes().repeat(48);producer.send(Message::Binary(samples.clone().into())).await?;
 tokio::time::timeout(std::time::Duration::from_secs(2),async {loop{match renderer.next().await.context("Speaker stream closed")??{Message::Binary(bytes)=>{ensure!(bytes.as_ref()==samples);break;},Message::Ping(bytes)=>renderer.send(Message::Pong(bytes)).await?,_=>{}}}Ok::<_,anyhow::Error>(())}).await??;
 case.app.collection("native_media_inventory").update_one(doc!{"_id":b},doc!{"$set":{"speaker_enabled":false}}).await?;
 tokio::time::timeout(std::time::Duration::from_secs(7),async {loop{match renderer.next().await{None|Some(Err(_))|Some(Ok(Message::Close(_)))=>break,Some(Ok(Message::Ping(bytes)))=>renderer.send(Message::Pong(bytes)).await?,_=>{}}}Ok::<_,anyhow::Error>(())}).await??;

 let report=case.status("POST","/api/media/client/report","",json!({"machine_id":b.to_hex(),"token":"speaker-b","protocol":2,"usb_enabled":false,"microphone_enabled":false,"speaker_enabled":false,"speaker_receiver_available":false,"receive_enabled":true,"receiver_available":false,"receiver_identity":null,"receiver_unavailable_reason":null,"sources":[],"states":[]}),StatusCode::OK).await?;
 ensure!(report["plans"].as_array().is_some_and(|rows|rows.iter().all(|r|r["id"]!=id)),"Revoked destination must not receive authorized plan");
 Ok(())}.await;
 case.db.drop().await?;result
}
