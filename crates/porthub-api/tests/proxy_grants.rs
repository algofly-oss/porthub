use anyhow::{ensure, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId};
use porthub_api::config::Config;
use serde_json::{json, Value};
mod support;
use support::Case;

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn proxy_sharing_requires_browser_authorization_and_stays_workspace_scoped() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result = async {
        let (owner, cookie) = case.user("proxy-owner@example.invalid", "user").await?;
        let (other, foreign_cookie) = case.user("proxy-other@example.invalid", "user").await?;
        let client = ObjectId::new(); let target = ObjectId::new(); let foreign = ObjectId::new();
        case.app.collection("machines").insert_many([
            doc! {"_id":client,"user_id":owner,"name":"Client"},
            doc! {"_id":target,"user_id":owner,"name":"Exit"},
            doc! {"_id":foreign,"user_id":other,"name":"Foreign"},
        ]).await?;
        let body = json!({"name":"Shared proxy","target_kind":"machine","target_machine_id":target.to_hex(),"client_machine_ids":[client.to_hex()]});
        let (status, _, _) = case.call("POST", "/api/access/proxy-grants", "", body.clone(), &[("authorization", "Bearer private-agent-token")]).await?;
        ensure!(status.is_client_error(), "agent credential created a proxy grant");
        case.status("POST", "/api/access/proxy-grants", &foreign_cookie, body.clone(), StatusCode::BAD_REQUEST).await?;
        case.status("POST","/api/access/proxy-grants",&cookie,json!({"name":"Unauthorized gateway LAN","client_machine_ids":[client.to_hex()],"allow_lan":true,"gateway_lan_authorized":true}),StatusCode::FORBIDDEN).await?;
        let saved = case.status("POST", "/api/access/proxy-grants", &cookie, body.clone(), StatusCode::OK).await?;
        ensure!(saved["allow_lan"] == false && saved["enabled"] == true);
        let route = format!("/api/access/proxy-grants/{}", saved["_id"].as_str().unwrap());
        case.status("PUT", &route, &foreign_cookie, json!({"name":"Foreign","client_machine_ids":[foreign.to_hex()]}), StatusCode::NOT_FOUND).await?;
        case.status("DELETE", &route, &foreign_cookie, Value::Null, StatusCode::NOT_FOUND).await?;
        let list = case.status("GET", "/api/access/proxy-grants", &cookie, Value::Null, StatusCode::OK).await?;
        ensure!(list["data"].as_array().unwrap().len() == 1);
        ensure!(list["can_allow_gateway_lan"]==false);
        let list = case.status("GET", "/api/access/proxy-grants", &foreign_cookie, Value::Null, StatusCode::OK).await?;
        ensure!(list["data"].as_array().unwrap().is_empty());
        let mut changed = body; changed["enabled"] = json!(false);
        case.status("PUT", &route, &cookie, changed, StatusCode::OK).await?;
        let list = case.status("GET", "/api/access/proxy-grants", &cookie, Value::Null, StatusCode::OK).await?;
        ensure!(list["data"][0]["enabled"] == false);
        case.status("DELETE", &route, &cookie, Value::Null, StatusCode::OK).await?;
        ensure!(case.app.collection("private_proxy_grants").count_documents(doc! {}).await? == 0);
        Ok::<_,anyhow::Error>(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB and host Docker bridge address via PORTHUB_TEST_PROXY_LAN_IP"]
async fn gateway_proxy_stream_is_authorized_duplex_and_revoked() -> Result<()> {
    use futures_util::{SinkExt, StreamExt};
    use std::future::IntoFuture;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::{
        connect_async,
        tungstenite::{client::IntoClientRequest, Message},
    };
    let case = Case::new(Config::default()).await?;
    let result =
        async {
            let (owner, cookie) = case.user("stream-owner@example.invalid", "admin").await?;
            let machine = ObjectId::new();
            let peer = format!("{owner}:{machine}");
            let token = "proxy-test-private-credential-0123456789";
            case.app
                .collection("machines")
                .insert_one(doc! {"_id":machine,"user_id":owner,"name":"Client","enabled":true})
                .await?;
            case.app.collection("private_peers").insert_one(doc! {
            "_id":&peer,"workspace_id":owner,"owner_id":owner,"machine_id":machine,"enabled":true,
            "credential_hash":porthub_api::domain::workspaces::token_digest(token),"ip":"10.239.0.2"
        }).await?;
            let saved = case.status("POST", "/api/access/proxy-grants", &cookie, json!({
            "name":"Gateway stream","client_machine_ids":[machine.to_hex()],"allow_lan":true
        }), StatusCode::OK).await?;
            let grant = saved["_id"].as_str().unwrap();
            let destination = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
            let port = destination.local_addr()?.port();
            let target_host = std::env::var("PORTHUB_TEST_PROXY_LAN_IP")?;
            let server = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let server_address = server.local_addr()?;
            let http = tokio::spawn(axum::serve(server, case.router.clone()).into_future());
            let request = |host: &str, credential: &str| -> Result<_> {
                let mut request = format!(
                    "ws://{server_address}/api/access/proxy-stream/{grant}?host={host}&port={port}"
                )
                .into_client_request()?;
                request
                    .headers_mut()
                    .insert("x-porthub-peer", peer.parse()?);
                request
                    .headers_mut()
                    .insert("authorization", format!("Bearer {credential}").parse()?);
                Ok(request)
            };
            for (host, credential) in [
                ("127.0.0.1", token),
                ("169.254.169.254", token),
                (target_host.as_str(), "wrong-private-credential-0123456789"),
            ] {
                ensure!(
                    connect_async(request(host, credential)?).await.is_err(),
                    "unauthorized target or credential accepted"
                );
            }
            // A legacy or manually forged gateway-LAN record has no trusted
            // approval marker and must not authorize streams.
            case.app.collection("private_proxy_grants").update_one(doc! {"_id":ObjectId::parse_str(grant)?},doc! {"$unset":{"gateway_lan_authorized":""}}).await?;
            ensure!(connect_async(request(&target_host,token)?).await.is_err(),"unapproved gateway LAN grant was consumed");
            case.status("PUT",&format!("/api/access/proxy-grants/{grant}"),&cookie,json!({"name":"Gateway stream","client_machine_ids":[machine.to_hex()],"allow_lan":true}),StatusCode::OK).await?;
            let destination_task = tokio::spawn(async move {
                let (mut socket, _) = destination.accept().await?;
                let mut buffer = [0u8; 32768];
                loop {
                    let length = socket.read(&mut buffer).await?;
                    if length == 0 {
                        break;
                    }
                    socket.write_all(&buffer[..length]).await?;
                }
                socket.write_all(b"after-half-close").await?;
                Ok::<_, anyhow::Error>(destination)
            });
            let (socket, _) = connect_async(request(&target_host, token)?).await?;
            let (mut writer, mut reader) = socket.split();
            let upload = async {
                for sequence in 0..128u8 {
                    writer
                        .send(Message::Binary(vec![sequence; 32768].into()))
                        .await?;
                }
                writer.send(Message::Text("eof".into())).await?;
                Ok::<_, anyhow::Error>(())
            };
            let download = async {
                let mut received = Vec::new();
                while let Some(message) = reader.next().await {
                    match message? {
                        Message::Binary(bytes) => received.extend_from_slice(&bytes),
                        Message::Text(text) if text == "eof" => break,
                        _ => {}
                    }
                }
                ensure!(
                    received.len() == 128 * 32768 + 16,
                    "duplex transfer length mismatch"
                );
                for (sequence, bytes) in received[..128 * 32768].chunks_exact(32768).enumerate() {
                    ensure!(
                        bytes.iter().all(|byte| *byte == sequence as u8),
                        "duplex transfer corruption"
                    );
                }
                ensure!(&received[128 * 32768..] == b"after-half-close");
                Ok::<_, anyhow::Error>(())
            };
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                tokio::try_join!(upload, download)
            })
            .await??;
            let destination = destination_task.await??;
            let remote_closed = tokio::spawn(async move {
                let (mut socket, _) = destination.accept().await?;
                let mut byte = [0u8; 1];
                socket.read_exact(&mut byte).await?;
                socket.write_all(b"ready").await?;
                ensure!(
                    socket.read(&mut byte).await? == 0,
                    "revoked destination remained open"
                );
                Ok::<_, anyhow::Error>(())
            });
            let (mut socket, _) = connect_async(request(&target_host, token)?).await?;
            socket.send(Message::Binary(vec![1].into())).await?;
            ensure!(matches!(socket.next().await, Some(Ok(Message::Binary(_)))));
            case.status(
                "DELETE",
                &format!("/api/access/proxy-grants/{grant}"),
                &cookie,
                Value::Null,
                StatusCode::OK,
            )
            .await?;
            let closed =
                tokio::time::timeout(std::time::Duration::from_secs(20), socket.next()).await?;
            ensure!(
                matches!(closed, None | Some(Err(_)) | Some(Ok(Message::Close(_)))),
                "revoked proxy stream stayed open"
            );
            remote_closed.await??;
            http.abort();
            let _ = http.await;
            Ok::<_, anyhow::Error>(())
        }
        .await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn peer_proxy_requires_the_selected_identity_before_forwarding() -> Result<()> {
    use futures_util::{SinkExt, StreamExt};
    use std::future::IntoFuture;
    use tokio_tungstenite::{connect_async,tungstenite::{client::IntoClientRequest,Message}};
    let case=Case::new(Config::default()).await?;
    let result=async {
        let (owner,cookie)=case.user("peer-proxy-owner@example.invalid","user").await?;
        let machines=[ObjectId::new(),ObjectId::new(),ObjectId::new()];
        let tokens=["client-test-token-01234567890123456789","target-test-token-01234567890123456789","other-test-token-01234567890123456789"];
        let fingerprint=vec!["AB";32].join(":");
        for (index,machine) in machines.iter().enumerate() {
            case.app.collection("machines").insert_one(doc! {"_id":machine,"user_id":owner,"name":format!("Peer{index}"),"enabled":true}).await?;
            case.app.collection("private_peers").insert_one(doc! {
                "_id":format!("proxy-peer-{index}"),"workspace_id":owner,"owner_id":owner,"machine_id":machine,"enabled":true,
                "credential_hash":porthub_api::domain::workspaces::token_digest(tokens[index]),"ip":format!("10.203.0.{}",index+10),
                "instance":"instance-0123456789","fingerprint":&fingerprint,"application_proxy":true
            }).await?;
        }
        let saved=case.status("POST","/api/access/proxy-grants",&cookie,json!({
            "name":"Peer stream","target_kind":"machine","target_machine_id":machines[1].to_hex(),"client_machine_ids":[machines[0].to_hex()]
        }),StatusCode::OK).await?;
        let grant=saved["_id"].as_str().unwrap();
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address=listener.local_addr()?;
        let http=tokio::spawn(axum::serve(listener,case.router.clone()).into_future());
        let request=|path:&str,index:usize|->Result<_> {
            let mut request=format!("ws://{address}{path}").into_client_request()?;
            request.headers_mut().insert("x-porthub-peer",format!("proxy-peer-{index}").parse()?);
            request.headers_mut().insert("authorization",format!("Bearer {}",tokens[index]).parse()?);
            Ok(request)
        };
        let sync=json!({"peer_id":"proxy-peer-1","token":tokens[1],"fingerprint":fingerprint,"instance":"instance-0123456789","application_proxy":true});
        let check_authorization=format!("Bearer {}",tokens[0]);
        let check_headers=[("x-porthub-peer","proxy-peer-0"),("authorization",check_authorization.as_str())];
        let status=case.status("POST","/api/access/private/sync","",sync.clone(),StatusCode::OK).await?;
        ensure!(status["proxy_provider"]==true);
        ensure!(connect_async(request("/api/access/proxy-jobs",0)?).await.is_err(),"unapproved machine subscribed as provider");
        let (status,_,check)=case.call("GET",&format!("/api/access/proxy-check/{grant}"),"",Value::Null,&check_headers).await?;
        ensure!(status==StatusCode::OK && check["ready"]==false,"provider was reported ready before notification subscription");
        let (mut notifications,_)=connect_async(request("/api/access/proxy-jobs",1)?).await?;
        let (status,_,check)=case.call("GET",&format!("/api/access/proxy-check/{grant}"),"",Value::Null,&check_headers).await?;
        ensure!(status==StatusCode::OK && check["ready"]==true,"provider readiness was not published");
        let client=tokio::spawn(connect_async(request(&format!("/api/access/proxy-stream/{grant}?host=example.test&port=443"),0)?));
        // No control sync occurs between requesting the stream and delivery.
        let session=match tokio::time::timeout(std::time::Duration::from_secs(2),notifications.next()).await? {
            Some(Ok(Message::Text(id)))=>id.to_string(),_=>anyhow::bail!("peer job was not notified immediately"),
        };
        let path=format!("/api/access/proxy-serve/{session}");
        ensure!(connect_async(request(&path,0)?).await.is_err(),"requester claimed the provider session");
        ensure!(connect_async(request(&path,2)?).await.is_err(),"unselected peer claimed the provider session");
        let (mut provider,_)=connect_async(request(&path,1)?).await?;
        let policy=match provider.next().await {Some(Ok(Message::Text(policy)))=>serde_json::from_str::<Value>(&policy)?,_=>anyhow::bail!("provider policy missing")};
        ensure!(policy["host"]=="example.test" && policy["port"]==443 && policy["allow_lan"]==false);
        ensure!(!policy.to_string().contains("token"));
        provider.send(Message::Text(json!({"destination_ip":"1.1.1.1"}).to_string().into())).await?;
        let (mut consumer,_)=client.await??;
        ensure!(connect_async(request(&path,1)?).await.is_err(),"provider session was reusable");
        consumer.send(Message::Binary(b"authenticated-peer-stream".to_vec().into())).await?;
        let bytes=match provider.next().await {Some(Ok(Message::Binary(bytes)))=>bytes,_=>anyhow::bail!("provider did not receive stream")};
        ensure!(&bytes[..]==b"authenticated-peer-stream");
        provider.send(Message::Binary(bytes)).await?;
        ensure!(matches!(consumer.next().await,Some(Ok(Message::Binary(_)))));
        // Both ends must lose access when the UI grant is deleted.
        case.status("DELETE",&format!("/api/access/proxy-grants/{grant}"),&cookie,Value::Null,StatusCode::OK).await?;
        let closed=tokio::time::timeout(std::time::Duration::from_secs(20),consumer.next()).await?;
        ensure!(matches!(closed,None|Some(Err(_))|Some(Ok(Message::Close(_)))),"revoked consumer stayed connected");
        let closed=tokio::time::timeout(std::time::Duration::from_secs(2),provider.next()).await?;
        ensure!(matches!(closed,None|Some(Err(_))|Some(Ok(Message::Close(_)))),"revoked provider stayed connected");
        http.abort();let _=http.await;
        Ok::<_,anyhow::Error>(())
    }.await;
    case.db.drop().await?;result
}
