use anyhow::{ensure,Result};
use axum::http::StatusCode;
use futures_util::{SinkExt,StreamExt};
use mongodb::bson::{doc,oid::ObjectId};
use serde_json::json;
use std::time::Duration;
use tokio_tungstenite::{MaybeTlsStream,WebSocketStream,tungstenite::{Message,client::IntoClientRequest}};
mod support;
use support::Case;
type Socket=WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
async fn connect(base:std::net::SocketAddr,id:&str,side:&str,machine:ObjectId,token:&str)->Result<Socket>{
 let mut request=format!("ws://{base}/api/usb/stream/{id}/{side}").into_client_request()?;
 request.headers_mut().insert("x-porthub-machine-id",machine.to_hex().parse()?);request.headers_mut().insert("authorization",format!("Bearer {token}").parse()?);Ok(tokio_tungstenite::connect_async(request).await?.0)
}
async fn frame(socket:&mut Socket)->Result<Message>{tokio::time::timeout(Duration::from_secs(2),async{loop{match socket.next().await.ok_or_else(||anyhow::anyhow!("USB socket closed"))??{Message::Ping(bytes)=>socket.send(Message::Pong(bytes)).await?,Message::Pong(_)=>{},frame=>return Ok::<_,anyhow::Error>(frame)}}}).await?}
#[tokio::test]
#[ignore="requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn equal_forward_ids_cannot_pair_different_owners_or_disrupt_their_cleanup()->Result<()>{
 let case=Case::new(Default::default()).await?;
 let result:Result<()>=async{
 let(owner_a,_)=case.user("usb-pair-a@example.invalid","user").await?;let(owner_b,_)=case.user("usb-pair-b@example.invalid","user").await?;
 let machines:[ObjectId;4]=std::array::from_fn(|_|ObjectId::new());let owners=[owner_a,owner_a,owner_b,owner_b];
 for(i,id)in machines.iter().enumerate(){case.app.collection("machines").insert_one(doc!{"_id":id,"user_id":owners[i],"enabled":true,"name":format!("Owned fixture {i}"),"token":format!("pair-token-{i}")}).await?;case.status("POST","/api/usb/client/report","",json!({"machine_id":id.to_hex(),"token":format!("pair-token-{i}"),"enabled":true,"supported":true,"devices":[],"states":[]}),StatusCode::OK).await?;}
 let id=uuid::Uuid::new_v4().simple().to_string();
 // Legacy CLI ids are caller-supplied. These are the exact ordinary Forward
 // records two independent owners can hold with the same public session id.
 for (slot,owner)in [(0,owner_a),(2,owner_b)]{case.app.collection("usb_forwards").insert_one(doc!{"_id":format!("fixture-{slot}"),"owner":owner,"id":&id,"source":machines[slot].to_hex(),"destination":machines[slot+1].to_hex(),"persistent":true,"device":{"busid":"1-2","vendor":"1377","product":"1100","serial":format!("fixture-{slot}"),"name":"Fixture","busnum":1,"devnum":2,"speed":3,"blocked":mongodb::bson::Bson::Null}}).await?;}
 let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let base=listener.local_addr()?;let router=case.router.clone();let _server=tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move{axum::serve(listener,router).await}));
 let mut source_a=connect(base,&id,"source",machines[0],"pair-token-0").await?;
 let mut destination_b=connect(base,&id,"destination",machines[3],"pair-token-3").await?;
 ensure!(tokio::time::timeout(Duration::from_millis(200),source_a.next()).await.is_err(),"Different owners sharing a session id were paired");
 ensure!(tokio::time::timeout(Duration::from_millis(200),destination_b.next()).await.is_err(),"Different owner received peer readiness");
 let mut destination_a=connect(base,&id,"destination",machines[1],"pair-token-1").await?;
 let mut source_b=connect(base,&id,"source",machines[2],"pair-token-2").await?;
 for peer in [&mut source_a,&mut destination_a,&mut source_b,&mut destination_b]{ensure!(frame(peer).await?==Message::Text("ready".into()));}
 source_a.send(Message::Binary(b"owner-a-only".to_vec().into())).await?;source_b.send(Message::Binary(b"owner-b-only".to_vec().into())).await?;
 ensure!(frame(&mut destination_a).await?==Message::Binary(b"owner-a-only".to_vec().into()));ensure!(frame(&mut destination_b).await?==Message::Binary(b"owner-b-only".to_vec().into()));
 source_a.close(None).await?;let _=frame(&mut destination_a).await;
 source_b.send(Message::Binary(b"owner-b-still-active".to_vec().into())).await?;
 ensure!(frame(&mut destination_b).await?==Message::Binary(b"owner-b-still-active".to_vec().into()),"One owner's cleanup removed another owner's active pair");
 Ok(())}.await;
 case.db.drop().await?;result
}

#[tokio::test]
#[ignore="requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn an_active_pair_cannot_keep_its_old_owner_key_after_transfer()->Result<()>{
 let case=Case::new(Default::default()).await?;
 let result:Result<()>=async{
 let(owner_a,_)=case.user("usb-transfer-a@example.invalid","user").await?;let(owner_b,_)=case.user("usb-transfer-b@example.invalid","user").await?;
 let source=ObjectId::new();let destination=ObjectId::new();let id=uuid::Uuid::new_v4().simple().to_string();
 for(machine,token)in [(source,"transfer-source"),(destination,"transfer-destination")]{case.app.collection("machines").insert_one(doc!{"_id":machine,"user_id":owner_a,"enabled":true,"name":"Transfer fixture","token":token}).await?;case.status("POST","/api/usb/client/report","",json!({"machine_id":machine.to_hex(),"token":token,"enabled":true,"supported":true,"devices":[],"states":[]}),StatusCode::OK).await?;}
 case.app.collection("usb_forwards").insert_one(doc!{"_id":"transfer-fixture","owner":owner_a,"id":&id,"source":source.to_hex(),"destination":destination.to_hex(),"persistent":true,"device":{"busid":"1-2","vendor":"1377","product":"1100","serial":"transfer-fixture","name":"Fixture","busnum":1,"devnum":2,"speed":3,"blocked":mongodb::bson::Bson::Null}}).await?;
 let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let base=listener.local_addr()?;let router=case.router.clone();let _server=tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move{axum::serve(listener,router).await}));
 let mut a=connect(base,&id,"source",source,"transfer-source").await?;let mut b=connect(base,&id,"destination",destination,"transfer-destination").await?;
 ensure!(frame(&mut a).await?==Message::Text("ready".into()));ensure!(frame(&mut b).await?==Message::Text("ready".into()));
 // Wait for the first reauthorization heartbeat so the coherent metadata
 // transfer finishes well before the next five-second check.
 for socket in [&mut a,&mut b]{let ping=tokio::time::timeout(Duration::from_secs(2),socket.next()).await?.ok_or_else(||anyhow::anyhow!("Missing heartbeat"))??;if let Message::Ping(bytes)=ping{socket.send(Message::Pong(bytes)).await?;}else{anyhow::bail!("Expected authorization heartbeat");}}
 case.app.collection("machines").update_many(doc!{"_id":{"$in":[source,destination]}},doc!{"$set":{"user_id":owner_b}}).await?;
 case.app.collection("usb_inventory").update_many(doc!{"_id":{"$in":[source,destination]}},doc!{"$set":{"owner":owner_b}}).await?;
 case.app.collection("usb_forwards").update_one(doc!{"_id":"transfer-fixture"},doc!{"$set":{"owner":owner_b}}).await?;
 let closed=tokio::time::timeout(Duration::from_secs(7),async{loop{match a.next().await{None|Some(Err(_))|Some(Ok(Message::Close(_)))=>return Ok::<(),anyhow::Error>(()),Some(Ok(Message::Ping(v)))=>a.send(Message::Pong(v)).await?,_=>{}}}}).await;
 ensure!(closed.is_ok(),"Reauthorization allowed an active pair to keep its previous owner's registry key");
 Ok(())}.await;
 case.db.drop().await?;result
}
