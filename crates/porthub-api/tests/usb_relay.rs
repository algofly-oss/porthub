use anyhow::{ensure,Result};
use axum::http::StatusCode;
use mongodb::bson::{doc,oid::ObjectId};
use serde_json::{json,Value};
mod support;
use support::Case;
#[tokio::test]
#[ignore="requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn relay_lineage_is_owner_bound_exclusive_acyclic_and_four_hops_only()->Result<()>{
 let case=Case::new(Default::default()).await?;
 let result:Result<()>=async{
 let(owner,cookie)=case.user("usb-relay-owner@example.invalid","user").await?;
 let ids:Vec<_>=(0..6).map(|_|ObjectId::new()).collect();let names:Vec<_>=ids.iter().map(|id|id.to_hex()).collect();
 for(i,id)in ids.iter().enumerate(){case.app.collection("machines").insert_one(doc!{"_id":id,"user_id":owner,"enabled":true,"name":format!("Relay fixture {i}"),"token":format!("relay-token-{i}")}).await?;}
 let device=json!({"busid":"2-3","vendor":"1377","product":"1100","serial":"stable-serial","name":"Fixture microphone","busnum":2,"devnum":3,"speed":3,"blocked":null});
 for(i,id)in names.iter().enumerate(){case.status("POST","/api/usb/client/report","",json!({"machine_id":id,"token":format!("relay-token-{i}"),"enabled":true,"supported":true,"devices":if i==0{vec![device.clone()]}else{vec![]},"states":[],"imports":[]}),StatusCode::OK).await?;}
 let shared_id="f".repeat(32);
 let root=case.status("POST","/api/usb/client/action","",json!({"machine_id":names[0],"token":"relay-token-0","action":"create","id":shared_id,"source":names[0],"destination":names[1],"busid":"2-3"}),StatusCode::OK).await?;
 let root_id=root["forward"]["id"].as_str().unwrap().to_owned();let mut parent=root_id.clone();let mut children=Vec::new();
 case.status("POST","/api/usb/client/relay-authorize","",json!({"machine_id":names[0],"token":"relay-token-0","id":root_id}),StatusCode::CONFLICT).await?;

 for hop in 1..=3{
 let alias=format!("0-{hop}");let mut imported=device.clone();imported["busid"]=alias.clone().into();
 let report=json!({"machine_id":names[hop],"token":format!("relay-token-{hop}"),"enabled":true,"supported":true,"devices":[imported],"states":[],"imports":[{"busid":alias,"upstream_id":parent}]});
 let assigned=case.status("POST","/api/usb/client/report","",report,StatusCode::OK).await?;ensure!(assigned["relay_version"]==1);
 case.status("POST","/api/usb/forwards",&cookie,json!({"source":names[hop],"destination":names[0],"busid":alias}),StatusCode::BAD_REQUEST).await?;
 let child=case.status("POST","/api/usb/forwards",&cookie,json!({"source":names[hop],"destination":names[hop+1],"busid":alias}),StatusCode::OK).await?;
 let id=child["forward"]["id"].as_str().unwrap().to_owned();ensure!(!child.to_string().contains("relay_parent"),"Private lineage leaked into strict old Forward DTO");
 let row=case.app.collection("usb_forwards").find_one(doc!{"id":&id}).await?.unwrap();ensure!(!row.contains_key("relay_parent"),"Old gateway Forward decoder must see no new fields");
 let mut legacy=row.clone();for field in ["_id","owner","expires_at"]{legacy.remove(field);}let decoded:porthub_components::usb::Forward=mongodb::bson::from_document(legacy)?;ensure!(decoded.id==id,"Strict old Forward decode failed");
 let metadata=case.app.collection("usb_relay_lineage").find_one(doc!{"forward_id":&id,"owner":owner}).await?.unwrap();ensure!(metadata.get_str("parent")==Ok(parent.as_str()));
 let authorization=case.status("POST","/api/usb/client/relay-authorize","",json!({"machine_id":names[hop],"token":format!("relay-token-{hop}"),"id":id}),StatusCode::OK).await?;ensure!(authorization["relay_version"]==1 && authorization["upstream_id"]==parent);
 if hop==1{case.status("POST","/api/usb/forwards",&cookie,json!({"source":names[hop],"destination":names[5],"busid":alias}),StatusCode::CONFLICT).await?;}
 parent=id.clone();children.push(id);
 }
 let mut imported=device.clone();imported["busid"]="0-4".into();case.status("POST","/api/usb/client/report","",json!({"machine_id":names[4],"token":"relay-token-4","enabled":true,"supported":true,"devices":[imported],"states":[],"imports":[{"busid":"0-4","upstream_id":parent}]}),StatusCode::OK).await?;
 case.status("POST","/api/usb/forwards",&cookie,json!({"source":names[4],"destination":names[5],"busid":"0-4"}),StatusCode::BAD_REQUEST).await?;
 // Every ancestor must retain both machine availability and its local USB
 // policy; a healthy B -> C endpoint pair cannot mask disabled original A.
 let changes:Vec<(&str,mongodb::bson::Document,&str,mongodb::bson::Bson,mongodb::bson::Bson)>=vec![
 ("machines",doc!{"_id":ids[0]},"enabled",false.into(),true.into()),
 ("machines",doc!{"_id":ids[0]},"deletion_pending",true.into(),false.into()),
 ("usb_inventory",doc!{"_id":ids[0]},"report.enabled",false.into(),true.into()),
 ("usb_inventory",doc!{"_id":ids[0]},"report.can_export",false.into(),true.into()),
 ("usb_inventory",doc!{"_id":ids[1]},"report.can_import",false.into(),true.into()),
 ("usb_inventory",doc!{"_id":ids[0]},"at",mongodb::bson::DateTime::from_millis(mongodb::bson::DateTime::now().timestamp_millis()-60000).into(),mongodb::bson::DateTime::now().into()),
 ];
 for (collection,filter,field,denied,restored) in changes {
 let mut update=mongodb::bson::Document::new();update.insert(field,denied);
 case.app.collection(collection).update_one(filter.clone(),doc!{"$set":update}).await?;
 case.status("POST","/api/usb/client/relay-authorize","",json!({"machine_id":names[1],"token":"relay-token-1","id":children[0]}),StatusCode::CONFLICT).await?;
 let mut update=mongodb::bson::Document::new();update.insert(field,restored);
 case.app.collection(collection).update_one(filter,doc!{"$set":update}).await?;
 case.status("POST","/api/usb/client/relay-authorize","",json!({"machine_id":names[1],"token":"relay-token-1","id":children[0]}),StatusCode::OK).await?;
 }
 // Reusing a parent ID for a different physical identity must not preserve
 // authority over a child's previously selected device.
 case.app.collection("usb_forwards").update_one(doc!{"owner":owner,"id":&root_id},doc!{"$set":{"device.serial":"replacement-device"}}).await?;
 case.status("POST","/api/usb/client/relay-authorize","",json!({"machine_id":names[1],"token":"relay-token-1","id":children[0]}),StatusCode::CONFLICT).await?;
 case.app.collection("usb_forwards").update_one(doc!{"owner":owner,"id":&root_id},doc!{"$set":{"device.serial":"stable-serial"}}).await?;
 case.status("POST","/api/usb/client/relay-authorize","",json!({"machine_id":names[1],"token":"relay-token-1","id":children[0]}),StatusCode::OK).await?;
 let (foreign_owner,_foreign_cookie)=case.user("usb-relay-foreign@example.invalid","user").await?;
 let foreign_source=ObjectId::new();let foreign_target=ObjectId::new();
 for (id,token) in [(foreign_source,"foreign-source"),(foreign_target,"foreign-target")] {
 case.app.collection("machines").insert_one(doc!{"_id":id,"user_id":foreign_owner,"enabled":true,"name":"Foreign relay fixture","token":token}).await?;
 case.status("POST","/api/usb/client/report","",json!({"machine_id":id.to_hex(),"token":token,"enabled":true,"supported":true,"devices":if id==foreign_source{vec![device.clone()]}else{vec![]},"states":[],"imports":[]}),StatusCode::OK).await?;
 }
 let foreign=case.status("POST","/api/usb/client/action","",json!({"machine_id":foreign_source.to_hex(),"token":"foreign-source","action":"create","id":shared_id,"source":foreign_source.to_hex(),"destination":foreign_target.to_hex(),"busid":"2-3"}),StatusCode::OK).await?;
 ensure!(case.app.collection("usb_relay_lineage").count_documents(doc!{"forward_id":&shared_id}).await?==2,"Forward IDs must be scoped by owner in private metadata");
 // Removing the ancestor revokes authentication but keeps orphan persistent
 // configuration visible so its owner can remove it normally.
 case.status("DELETE",&format!("/api/usb/forwards/{root_id}"),&cookie,Value::Null,StatusCode::OK).await?;
 let visible=case.status("GET","/api/usb/forwards",&cookie,Value::Null,StatusCode::OK).await?;ensure!(visible["forwards"].as_array().unwrap().len()==3);
 use tokio_tungstenite::tungstenite::client::IntoClientRequest;
 let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let base=listener.local_addr()?;let router=case.router.clone();let _server=tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move{axum::serve(listener,router).await}));
 let mut request=format!("ws://{base}/api/usb/stream/{}/source",children[0]).into_client_request()?;request.headers_mut().insert("x-porthub-machine-id",names[1].parse()?);request.headers_mut().insert("authorization","Bearer relay-token-1".parse()?);
 ensure!(tokio_tungstenite::connect_async(request).await.is_err(),"Orphan child retained stream authority");
 case.status("POST","/api/usb/client/relay-authorize","",json!({"machine_id":names[1],"token":"relay-token-1","id":children[0]}),StatusCode::CONFLICT).await?;
 // Reserved imported aliases never silently become ordinary physical exports.
 let mut forged=device.clone();forged["busid"]="0-88".into();
 case.status("POST","/api/usb/client/report","",json!({"machine_id":names[5],"token":"relay-token-5","enabled":true,"supported":true,"devices":[forged],"states":[],"imports":[{"busid":"0-88","upstream_id":foreign["forward"]["id"]}]}),StatusCode::OK).await?;
 case.status("POST","/api/usb/forwards",&cookie,json!({"source":names[5],"destination":names[0],"busid":"0-88"}),StatusCode::CONFLICT).await?;
 let mut unknown=device;unknown["busid"]="0-99".into();case.status("POST","/api/usb/client/report","",json!({"machine_id":names[5],"token":"relay-token-5","enabled":true,"supported":true,"devices":[unknown],"states":[],"imports":[]}),StatusCode::BAD_REQUEST).await?;
 Ok(())}.await;
 case.db.drop().await?;result
}
