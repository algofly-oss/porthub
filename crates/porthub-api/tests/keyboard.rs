use anyhow::{ensure, Result};
use axum::http::StatusCode;
use futures_util::{SinkExt, StreamExt};
use mongodb::bson::{doc, oid::ObjectId};
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
async fn next(socket: &mut Socket) -> Result<Value> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let frame = socket
                .next()
                .await
                .ok_or_else(|| anyhow::anyhow!("socket closed"))??;
            if let Message::Text(text) = frame {
                let value: Value = serde_json::from_str(&text)?;
                if value["type"] == "ping" {
                    socket
                        .send(Message::Text(json!({"type":"pong"}).to_string().into()))
                        .await?;
                    continue;
                }
                return Ok(value);
            }
        }
    })
    .await?
}
async fn send(socket: &mut Socket, value: Value) -> Result<()> {
    socket.send(Message::Text(value.to_string().into())).await?;
    Ok(())
}
async fn controller(
    base: &str,
    target: &str,
    cookie: &str,
    origin: Option<&str>,
) -> Result<Socket> {
    let mut req = format!("{base}/api/keyboard/control/{target}").into_client_request()?;
    req.headers_mut().insert("cookie", cookie.parse()?);
    if let Some(origin) = origin {
        req.headers_mut().insert("origin", origin.parse()?);
    }
    Ok(connect_async(req).await?.0)
}
#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn ownership_exclusive_control_acknowledgement_and_revocation() -> Result<()> {
    let case = Case::new(Default::default()).await?;
    let result:Result<()>=async{
        let(owner,cookie)=case.user("keyboard-owner@example.invalid","admin").await?;let(_,other)=case.user("keyboard-other@example.invalid","user").await?;
        let machine=ObjectId::new();let id=machine.to_hex();let token="machine-keyboard-fixture";
        case.app.collection("machines").insert_one(doc!{"_id":machine,"name":"Test desktop","token":token,"user_id":owner,"enabled":true}).await?;
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let base=format!("ws://{}",listener.local_addr()?);let router=case.router.clone();let _server=tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move{axum::serve(listener,router).await}));
        ensure!(connect_async(format!("{base}/api/keyboard/host")).await.is_err());
        let mut req=format!("{base}/api/keyboard/host").into_client_request()?;req.headers_mut().insert("x-porthub-machine-id",id.parse()?);req.headers_mut().insert("authorization",format!("Bearer {token}").parse()?);
        let(mut host,_)=connect_async(req).await?;ensure!(next(&mut host).await?["type"]=="ready");
        ensure!(controller(&base,&id,&other,None).await.is_err(),"network visibility must not confer HID ownership");
        ensure!(controller(&base,&id,&cookie,Some("https://foreign.invalid")).await.is_err(),"cross-origin management must fail");
        let mut client=controller(&base,&id,&cookie,None).await?;let ready=next(&mut client).await?;ensure!(ready["type"]=="ready");let start=next(&mut host).await?;ensure!(start["type"]=="start");
        ensure!(controller(&base,&id,&cookie,None).await.is_err(),"one controller per desktop");
        let input=json!({"id":uuid::Uuid::new_v4().to_string(),"command":{"type":"clipboard","text":"https://example.invalid/link","paste":true}});
        send(&mut client,json!({"type":"input","input":input})).await?;let forwarded=next(&mut host).await?;ensure!(forwarded["input"]==input && forwarded["session"]==start["session"]);
        send(&mut host,json!({"type":"ack","session":start["session"],"ack":{"id":input["id"],"ok":true}})).await?;let ack=next(&mut client).await?;ensure!(ack["ack"]["id"]==input["id"]);
        send(&mut client,json!({"type":"input","input":{"id":uuid::Uuid::new_v4().to_string(),"command":{"type":"text","text":"x".repeat(8193)}}})).await?;ensure!(next(&mut client).await?["type"]=="error");
        send(&mut client,json!({"type":"direct_offer","description":"{\"type\":\"offer\",\"sdp\":\"test\"}"})).await?;ensure!(next(&mut host).await?["type"]=="direct_offer");
        client.close(None).await?;ensure!(next(&mut host).await?["type"]=="stop");host.close(None).await?;
        let board=case.status("POST","/api/keyboard/devices",&cookie,json!({"name":"USB keyboard"}),StatusCode::OK).await?;let board_id=board["id"].as_str().unwrap();
        let row=case.app.collection("keyboard_devices").find_one(doc!{"_id":board_id}).await?.unwrap();ensure!(!row.contains_key("token")&&row.get_str("token_hash")?.len()==64);
        case.status("DELETE",&format!("/api/keyboard/devices/{board_id}"),&other,Value::Null,StatusCode::CONFLICT).await?;
        let mut request=format!("{base}/api/keyboard/device/{board_id}").into_client_request()?;request.headers_mut().insert("authorization",format!("Bearer {}",board["token"].as_str().unwrap()).parse()?);let(mut device,_)=connect_async(request).await?;ensure!(next(&mut device).await?["type"]=="ready");
        let listed=case.status("GET","/api/keyboard/targets",&cookie,Value::Null,StatusCode::OK).await?;ensure!(!listed.to_string().contains(board["token"].as_str().unwrap()));
        case.status("DELETE",&format!("/api/keyboard/devices/{board_id}"),&cookie,Value::Null,StatusCode::OK).await?;
        ensure!(tokio::time::timeout(Duration::from_secs(3),device.next()).await?.is_some());
        let settings=case.status("GET","/api/keyboard/speech",&cookie,Value::Null,StatusCode::OK).await?;ensure!(settings["loaded"]==false && settings["settings"]["enabled"]==true && settings["settings"]["model"]=="whisper-tiny");
        case.status("PATCH","/api/keyboard/speech",&other,json!({"enabled":false,"model":"whisper-tiny","engine":"cpu"}),StatusCode::FORBIDDEN).await?;
        let disabled=case.status("PATCH","/api/keyboard/speech",&cookie,json!({"enabled":false,"model":"moonshine-tiny","engine":"cpu"}),StatusCode::OK).await?;ensure!(disabled["loaded"]==false && disabled["settings"]["enabled"]==false);
        let saved=case.app.collection("settings").find_one(doc!{"_id":"keyboard_speech"}).await?.unwrap();ensure!(saved.get_document("settings")?.get_bool("enabled")==Ok(false));
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}
