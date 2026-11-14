use anyhow::{ensure, Result};
use axum::http::StatusCode;
use futures_util::{SinkExt, StreamExt};
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use serde_json::{json, Value};
use std::time::Duration;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, Message},
    MaybeTlsStream, WebSocketStream,
};
mod support;
use support::Case;
type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
async fn socket(base: &str, id: &str, side: &str, machine: &str, token: &str) -> Result<Socket> {
    let mut request = format!("{base}/api/usb/stream/{id}/{side}").into_client_request()?;
    request
        .headers_mut()
        .insert("x-porthub-machine-id", machine.parse()?);
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {token}").parse()?);
    Ok(connect_async(request).await?.0)
}
async fn frame(socket: &mut Socket) -> Result<Message> {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            match socket
                .next()
                .await
                .ok_or_else(|| anyhow::anyhow!("USB socket closed"))??
            {
                Message::Ping(b) => socket.send(Message::Pong(b)).await?,
                Message::Pong(_) => {}
                value => return Ok::<_, anyhow::Error>(value),
            }
        }
    })
    .await?
}
#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn owned_device_reservations_authenticated_streams_and_revocation() -> Result<()> {
    let case = Case::new(Default::default()).await?;
    let result:Result<()>=async{
  let(owner,cookie)=case.user("usb-owner@example.invalid","user").await?;let(other_owner,other_cookie)=case.user("usb-other@example.invalid","user").await?;
  let source=ObjectId::new();let destination=ObjectId::new();let foreign=ObjectId::new();let source_id=source.to_hex();let destination_id=destination.to_hex();let foreign_id=foreign.to_hex();
  for(id,owner,name,token)in[(source,owner,"USB source","source-token"),(destination,owner,"USB destination","destination-token"),(foreign,other_owner,"Other owner's machine","foreign-token")]{case.app.collection("machines").insert_one(doc!{"_id":id,"user_id":owner,"enabled":true,"name":name,"token":token}).await?;}
  let device=json!({"busid":"2-3","vendor":"1377","product":"1100","serial":"stable-serial","name":"Test microphone","busnum":2,"devnum":3,"speed":3,"blocked":null});
  let report=json!({"machine_id":source_id,"token":"source-token","enabled":true,"supported":true,"devices":[device],"states":[]});
  let blank=case.status("POST","/api/usb/client/report","",report.clone(),StatusCode::OK).await?;ensure!(blank["forwards"].as_array().unwrap().is_empty());
  let data=case.status("GET","/api/usb/inventory",&cookie,Value::Null,StatusCode::OK).await?;ensure!(data["machines"].as_array().unwrap().len()==2&&!data.to_string().contains("source-token"));
  let command=json!({"source":source_id,"destination":destination_id,"busid":"2-3"});
  case.status("POST","/api/usb/forwards",&other_cookie,command.clone(),StatusCode::CONFLICT).await?;
  let mut cross=command.clone();cross["destination"]=foreign_id.clone().into();case.status("POST","/api/usb/forwards",&cookie,cross,StatusCode::CONFLICT).await?;
  let created=case.status("POST","/api/usb/forwards",&cookie,command.clone(),StatusCode::OK).await?;let id=created["forward"]["id"].as_str().unwrap();
  ensure!(created["forward"]["persistent"]==true);case.status("POST","/api/usb/forwards",&cookie,command.clone(),StatusCode::CONFLICT).await?;
  let ready=case.status("POST","/api/usb/client/report","",report.clone(),StatusCode::OK).await?;ensure!(ready["forwards"][0]["id"]==id,"database fields must not break typed forwarding contracts");
  let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let base=format!("ws://{}",listener.local_addr()?);let router=case.router.clone();let _server=tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move{axum::serve(listener,router).await}));
  ensure!(socket(&base,id,"source",&foreign_id,"foreign-token").await.is_err());ensure!(socket(&base,id,"source",&source_id,"bad-token").await.is_err());ensure!(socket(&base,id,"source",&destination_id,"destination-token").await.is_err());
  let mut a=socket(&base,id,"source",&source_id,"source-token").await?;let mut b=socket(&base,id,"destination",&destination_id,"destination-token").await?;
  ensure!(matches!(frame(&mut a).await?,Message::Text(t) if t.as_str()=="ready"));ensure!(matches!(frame(&mut b).await?,Message::Text(t) if t.as_str()=="ready"));
  a.send(Message::Text(json!({"type":"offer","sdp":"authenticated-offer"}).to_string().into())).await?;ensure!(matches!(frame(&mut b).await?,Message::Text(t) if t.contains("authenticated-offer")));
  let bytes:Vec<u8>=(0..16384).map(|i|(i%251)as u8).collect();a.send(Message::Binary(bytes.clone().into())).await?;ensure!(matches!(frame(&mut b).await?,Message::Binary(v) if v.as_ref()==bytes.as_slice()));b.send(Message::Binary(b"reverse-traffic".to_vec().into())).await?;ensure!(matches!(frame(&mut a).await?,Message::Binary(v) if v.as_ref()==b"reverse-traffic"));
  let mut duplicate=socket(&base,id,"source",&source_id,"source-token").await?;ensure!(tokio::time::timeout(Duration::from_secs(2),duplicate.next()).await?.is_some());
  case.status("DELETE",&format!("/api/usb/forwards/{id}"),&other_cookie,Value::Null,StatusCode::OK).await?;ensure!(case.status("GET","/api/usb/forwards",&cookie,Value::Null,StatusCode::OK).await?["forwards"].as_array().unwrap().len()==1);
  case.status("DELETE",&format!("/api/usb/forwards/{id}"),&cookie,Value::Null,StatusCode::OK).await?;
  ensure!(matches!(frame(&mut a).await,Ok(Message::Close(_))|Err(_)),"deleting a rule revokes live relay traffic");
  let temporary=uuid::Uuid::new_v4().simple().to_string();let action=json!({"machine_id":source_id,"token":"source-token","action":"create","id":temporary,"source":source_id,"destination":destination_id,"busid":"2-3"});
  let created=case.status("POST","/api/usb/client/action","",action.clone(),StatusCode::OK).await?;ensure!(created["forward"]["persistent"]==false);case.status("POST","/api/usb/client/action","",action,StatusCode::OK).await?;
  case.app.collection("usb_forwards").update_one(doc!{"id":&temporary},doc!{"$set":{"expires_at":DateTime::from_millis(1)}}).await?;
  ensure!(case.status("GET","/api/usb/forwards",&cookie,Value::Null,StatusCode::OK).await?["forwards"].as_array().unwrap().is_empty(),"expired temporary leases must not survive a CLI crash");
  let mut blocked=report;blocked["devices"][0]["blocked"]="Mounted storage device".into();case.status("POST","/api/usb/client/report","",blocked,StatusCode::OK).await?;case.status("POST","/api/usb/forwards",&cookie,command,StatusCode::CONFLICT).await?;
  Ok(())
 }.await;
    case.db.drop().await?;
    result
}
