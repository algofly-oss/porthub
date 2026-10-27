use anyhow::{bail, ensure, Context, Result};
use axum::http::StatusCode;
use futures_util::{SinkExt, StreamExt};
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use porthub_api::{config::Config, realtime::*};
use serde_json::{json, Value};
use std::{net::SocketAddr, time::Duration};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, Message},
    MaybeTlsStream, WebSocketStream,
};
mod support;
use support::Case;
struct Wire(WebSocketStream<MaybeTlsStream<TcpStream>>);
impl Wire {
    async fn open(
        address: SocketAddr,
        cookie: &str,
        auth: Value,
        origin: Option<&str>,
    ) -> Result<(Self, bool)> {
        let mut request =
            format!("ws://{address}/socket.io/?EIO=4&transport=websocket").into_client_request()?;
        if !cookie.is_empty() {
            request.headers_mut().insert("cookie", cookie.parse()?);
        }
        if let Some(origin) = origin {
            request.headers_mut().insert("origin", origin.parse()?);
        }
        let (stream, _) = connect_async(request).await?;
        let mut wire = Self(stream);
        let open = wire.frame().await?;
        ensure!(open.starts_with('0'));
        let data: Value = serde_json::from_str(&open[1..])?;
        ensure!(
            data["pingInterval"] == 25000
                && data["pingTimeout"] == 20000
                && data["maxPayload"] == 1_000_000
        );
        wire.0
            .send(Message::Text(format!("40{auth}").into()))
            .await?;
        let connect = wire.frame().await?;
        if connect.starts_with("44") {
            return Ok((wire, false));
        }
        ensure!(
            connect.starts_with("40"),
            "invalid namespace acknowledgement: {connect}"
        );
        wire.expect("join").await?;
        Ok((wire, true))
    }
    async fn frame(&mut self) -> Result<String> {
        tokio::time::timeout(Duration::from_secs(3), async {
            while let Some(message) = self.0.next().await {
                match message? {
                    Message::Text(text) if text == "2" => {
                        self.0.send(Message::Text("3".into())).await?
                    }
                    Message::Text(text) => return Ok(text.to_string()),
                    Message::Close(_) => bail!("socket closed"),
                    _ => {}
                }
            }
            bail!("socket ended")
        })
        .await?
    }
    async fn emit(&mut self, event: &str, data: Option<Value>) -> Result<()> {
        let args = match data {
            Some(data) => json!([event, data]),
            None => json!([event]),
        };
        self.0
            .send(Message::Text(format!("42{args}").into()))
            .await?;
        Ok(())
    }
    async fn expect(&mut self, event: &str) -> Result<Value> {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let frame = self.frame().await?;
                let Some(frame) = frame.strip_prefix("42") else {
                    continue;
                };
                let args: Vec<Value> = serde_json::from_str(frame)?;
                if args.first() == Some(&json!(event)) {
                    return Ok(args.get(1).cloned().unwrap_or(Value::Null));
                }
            }
        })
        .await?
    }
    async fn quiet(&mut self) -> Result<()> {
        ensure!(
            tokio::time::timeout(Duration::from_millis(100), self.frame())
                .await
                .is_err(),
            "unauthorized or unexpected event delivered"
        );
        Ok(())
    }
    async fn disconnected(&mut self, forbidden: Option<&str>) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                match self.frame().await {
                    Ok(frame) => {
                        if let Some(secret) = forbidden {
                            ensure!(
                                !frame.contains(secret),
                                "revoked socket received new credentials"
                            );
                        }
                        if frame == "41" {
                            return Ok(());
                        }
                    }
                    Err(_) => return Ok(()),
                }
            }
        })
        .await?
    }
    async fn close(mut self) {
        let _ = self.0.close(None).await;
    }
}
async fn serving(case: &Case) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let router = case.router.clone();
    Ok((
        address,
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        }),
    ))
}
fn api_error(error: porthub_api::error::ApiError) -> anyhow::Error {
    anyhow::anyhow!("{}", error.detail)
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn idle_expiry_and_recovery_push_owner_status_without_a_client_request() -> Result<()> {
    let case = Case::new(Config {
        machine_online_ttl_millis: 1000,
        ..Config::default()
    })
    .await?;
    let (address, server) = serving(&case).await?;
    let result = async {
        let (owner, cookie) = case.user("monitor-owner@example.invalid", "user").await?;
        let (_, foreign_cookie) = case.user("monitor-foreign@example.invalid", "user").await?;
        let id = ObjectId::new();
        case.app
            .collection("machines")
            .insert_one(doc! {"_id":id,"user_id":owner,"name":"Expires",
            "token":"private-secret","last_seen_at":DateTime::now()})
            .await?;
        let (mut user, accepted) = Wire::open(address, &cookie, json!({}), None).await?;
        ensure!(accepted);
        let (mut foreign, accepted) = Wire::open(address, &foreign_cookie, json!({}), None).await?;
        ensure!(accepted);
        let mut monitor = porthub_api::status_monitor::Monitor::default();
        monitor
            .tick(&case.app, DateTime::now())
            .await
            .map_err(api_error)?;
        user.quiet().await?;
        case.app
            .collection("machines")
            .update_one(
                doc! {"_id":id},
                doc! {"$set":{"last_seen_at":DateTime::from_millis(0)}},
            )
            .await?;
        monitor
            .tick(&case.app, DateTime::now())
            .await
            .map_err(api_error)?;
        let expired = user.expect(STC_CHANGED).await?;
        ensure!(
            expired["machine"]["_id"] == id.to_hex()
                && expired["machine"]["connection_status"] == "offline"
        );
        case.app
            .collection("machines")
            .update_one(
                doc! {"_id":id},
                doc! {"$set":{"last_seen_at":DateTime::now(),"auth_required":true}},
            )
            .await?;
        monitor
            .tick(&case.app, DateTime::now())
            .await
            .map_err(api_error)?;
        let recovered = user.expect(STC_CHANGED).await?;
        ensure!(
            recovered["machine"]["connection_status"] == "auth_required"
                && recovered["machine"]["is_active"] == true
        );
        foreign.quiet().await?;
        user.close().await;
        foreign.close().await;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    case.app.realtime.close().await;
    server.abort();
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn websocket_authentication_and_event_scopes_separate_users_and_machines() -> Result<()> {
    let case = Case::new(Config {
        public_base_url: "http://hub.example.invalid".into(),
        ..Default::default()
    })
    .await?;
    let (address, task) = serving(&case).await?;
    let result=async {
        let (owner,cookie)=case.user("socket-owner@test.invalid","user").await?;
        let (foreign,other_cookie)=case.user("socket-other@test.invalid","user").await?;
        let own=ObjectId::new();let other=ObjectId::new();let deleted=ObjectId::new();
        case.app.collection("machines").insert_many([
            doc! {"_id":own,"user_id":owner,"name":"Luna","token":"own-secret","enabled":true},
            doc! {"_id":other,"user_id":foreign,"name":"Miro","token":"other-secret","enabled":true},
            doc! {"_id":deleted,"user_id":owner,"name":"Deleted","token":"deleted-secret","enabled":false,"deletion_pending":true}]).await?;
        let own_record=case.app.collection("machines").find_one(doc! {"_id":own}).await?.unwrap();
        let connection=doc! {"_id":ObjectId::new(),"machine_id":own,"internal_port":8080,"external_port":39119,"enabled":true};
        case.app.collection("connections").insert_one(connection).await?;
        let (anonymous,accepted)=Wire::open(address,"",json!({}),None).await?;ensure!(!accepted);anonymous.close().await;
        let (evil,accepted)=Wire::open(address,&cookie,json!({}),Some("https://evil.invalid")).await?;ensure!(!accepted);evil.close().await;
        let (wrong,accepted)=Wire::open(address,"",json!({"role":"machine","machine_id":own.to_hex(),"token":"wrong"}),None).await?;ensure!(!accepted);wrong.close().await;
        let origin=format!("http://{address}");
        let (mut browser,accepted)=Wire::open(address,&cookie,json!({}),Some(&origin)).await?;ensure!(accepted);
        let (mut other_browser,accepted)=Wire::open(address,&other_cookie,json!({}),Some(&origin)).await?;ensure!(accepted);
        let (mut machine,accepted)=Wire::open(address,"",json!({"role":"machine","machine_id":own.to_hex(),"token":"own-secret"}),None).await?;ensure!(accepted);
        browser.emit(CTS_STATUS,None).await?;
        let snapshot=browser.expect(STC_STATUS).await?;
        ensure!(snapshot["machines"].as_array().unwrap().len()==1 && snapshot["machines"][0]["_id"]==own.to_hex());
        machine.emit(CTS_CONFIG,Some(json!({"machine_id":other.to_hex()}))).await?;
        let config=machine.expect(STC_CONFIG).await?;
        ensure!(config["machine_id"]==own.to_hex() && config["config"]["machine_id"]==own.to_hex());
        ensure!(config["config"]["files"]["client.toml"].as_str().context("TOML")?.contains("own-secret"));
        ensure!(!config.to_string().contains("other-secret"));
        machine.emit(CTS_STATUS,None).await?;machine.emit(CTS_SUBSCRIBE,Some(json!({"machine_id":own.to_hex()}))).await?;
        browser.emit(CTS_CONFIG,None).await?;browser.emit(CTS_SUBSCRIBE,Some(json!({"machine_id":other.to_hex()}))).await?;
        machine.quiet().await?;browser.quiet().await?;
        ensure!(!case.app.realtime.log_requested(&case.app,&own.to_hex()).await.map_err(api_error)?);
        ensure!(!case.app.realtime.log_requested(&case.app,&other.to_hex()).await.map_err(api_error)?);
        case.app.notify_status(&own_record).await;
        ensure!(browser.expect(STC_CHANGED).await?["machine"]["_id"]==own.to_hex());
        other_browser.quiet().await?;machine.quiet().await?;
        browser.close().await;other_browser.close().await;machine.close().await;
        Ok(())
    }.await;
    case.app.realtime.close().await;
    task.abort();
    let _ = task.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn log_subscriptions_are_reference_counted_scoped_and_cleaned_on_disconnect() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let (address, task) = serving(&case).await?;
    let result=async {
        let (owner,cookie)=case.user("logs-owner@test.invalid","user").await?;
        let (foreign,other_cookie)=case.user("logs-other@test.invalid","user").await?;
        let id=ObjectId::new();let other=ObjectId::new();
        case.app.collection("machines").insert_many([
            doc! {"_id":id,"user_id":owner,"name":"Luna","token":"current","log_tokens":["previous"],"enabled":true},
            doc! {"_id":other,"user_id":foreign,"name":"Other","token":"other-current","enabled":true}]).await?;
        let (mut first,accepted)=Wire::open(address,&cookie,json!({}),None).await?;ensure!(accepted);
        let (mut second,accepted)=Wire::open(address,&cookie,json!({}),None).await?;ensure!(accepted);
        let (mut outsider,accepted)=Wire::open(address,&other_cookie,json!({}),None).await?;ensure!(accepted);
        for socket in [&mut first,&mut second] {
            socket.emit(CTS_SUBSCRIBE,Some(json!({"machine_id":id.to_hex()}))).await?;
            let status=socket.expect(STC_LOG_STATUS).await?;ensure!(status["subscribed"]==true && status["stream_requested"]==true);
        }
        outsider.emit(CTS_SUBSCRIBE,Some(json!({"machine_id":id.to_hex()}))).await?;outsider.quiet().await?;
        first.emit(CTS_UNSUBSCRIBE,Some(json!({"machine_id":id.to_hex()}))).await?;
        let status=first.expect(STC_LOG_STATUS).await?;ensure!(status["subscribed"]==false && status["stream_requested"]==true);
        first.close().await;
        let before=case.app.collection("machines").find_one(doc! {"_id":id}).await?.unwrap();
        case.status("POST","/api/machines/client/logs","",json!({"machine_id":id.to_hex(),"token":"unrelated","lines":["forged"]}),StatusCode::UNAUTHORIZED).await?;
        ensure!(case.app.collection("machines").find_one(doc! {"_id":id}).await?.unwrap()==before);
        let (status,headers,body)=case.call("GET",&format!("/api/machines/client/log-stream?machine_id={id}&token=previous"),"",Value::Null,&[]).await?;
        ensure!(status==StatusCode::OK && headers["x-porthub-machine-auth-required"]=="true" && headers["x-porthub-log-stream-active"]=="true" && body["active"]==true);
        ensure!(case.app.collection("machines").find_one(doc! {"_id":id}).await?.unwrap().get_bool("auth_required")?);
        let mut lines=vec![" \r\n".to_owned(),"  first\r\n".into(),"é".repeat(4001)];
        lines.extend((0..110).map(|i|format!("line-{i}")));
        let uploaded=case.status("POST","/api/machines/client/logs","",json!({"machine_id":id.to_hex(),"token":"current","source":"é".repeat(33),"lines":lines}),StatusCode::OK).await?;
        ensure!(uploaded["data"]["count"]==99);
        let first_line=second.expect(STC_LOG_LINE).await?;ensure!(first_line["line"]=="  first" && first_line["source"]=="é".repeat(32));
        let unicode=second.expect(STC_LOG_LINE).await?;ensure!(unicode["line"]=="é".repeat(4000));
        for _ in 0..97 {second.expect(STC_LOG_LINE).await?;}
        outsider.quiet().await?;
        second.close().await;
        tokio::time::timeout(Duration::from_secs(2),async {
            while case.app.realtime.log_requested(&case.app,&id.to_hex()).await.map_err(api_error)? {tokio::time::sleep(Duration::from_millis(5)).await;}
            Ok::<(),anyhow::Error>(())
        }).await??;
        let status=case.status("GET",&format!("/api/machines/client/log-stream?machine_id={id}&token=current"),"",Value::Null,StatusCode::OK).await?;
        ensure!(status["active"]==false);
        outsider.close().await;
        Ok(())
    }.await;
    case.app.realtime.close().await;
    task.abort();
    let _ = task.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn configuration_changes_and_revocation_reach_only_live_authorized_sockets() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let case = Case::new(Config {
        gateway_config_path: Some(temporary.path().join("gateway.toml")),
        public_base_url: "http://hub.invalid".into(),
        ..Default::default()
    })
    .await?;
    let (address, task) = serving(&case).await?;
    let result=async {
        let (owner,cookie)=case.user("revocation-owner@test.invalid","user").await?;let id=ObjectId::new();
        case.app.collection("machines").insert_one(doc! {"_id":id,"user_id":owner,"name":"Luna","token":"original","enabled":true}).await?;
        let (mut browser,accepted)=Wire::open(address,&cookie,json!({}),None).await?;ensure!(accepted);
        let (mut machine,accepted)=Wire::open(address,"",json!({"role":"machine","machine_id":id.to_hex(),"token":"original"}),None).await?;ensure!(accepted);
        let mapped=case.status("POST","/api/connections/add",&cookie,json!({"machine_id":id.to_hex(),"service_name":"Files","internal_ip":"127.0.0.1","internal_port":8080,"external_port":39119}),StatusCode::OK).await?;
        let change=machine.expect(STC_CONFIG_CHANGED).await?;ensure!(change["machine_id"]==id.to_hex() && change["config"]["connections"].as_array().unwrap().len()==1);
        case.status("POST","/api/connections/delete",&cookie,json!({"data_id":mapped["data"]["_id"]}),StatusCode::OK).await?;
        ensure!(machine.expect(STC_CONFIG_CHANGED).await?["config"]["connections"]==json!([]));
        let rotated=case.status("POST","/api/machines/refresh-token",&cookie,json!({"data_id":id.to_hex()}),StatusCode::OK).await?;
        let token=rotated["data"]["token"].as_str().context("rotated token")?;
        machine.disconnected(Some(token)).await?;
        ensure!(browser.expect(STC_CHANGED).await?["machine"]["token"]==token);
        browser.emit(CTS_SUBSCRIBE,Some(json!({"machine_id":id.to_hex()}))).await?;browser.expect(STC_LOG_STATUS).await?;
        case.status("POST","/api/auth/signout",&cookie,json!({}),StatusCode::OK).await?;
        browser.disconnected(None).await?;
        ensure!(!case.app.realtime.log_requested(&case.app,&id.to_hex()).await.map_err(api_error)?);
        browser.close().await;machine.close().await;
        Ok(())
    }.await;
    case.app.realtime.close().await;
    task.abort();
    let _ = task.await;
    case.db.drop().await?;
    result
}

#[test]
fn log_line_bounds_preserve_whitespace_unicode_and_first_hundred_input_lines() {
    let mut lines = vec![" \n".into(), "  keep  \r\n".into(), "é".repeat(4001)];
    lines.extend((0..110).map(|i| format!("{i}")));
    let clean = porthub_api::domain::machine_logs::clean(lines);
    assert_eq!(clean.len(), 99);
    assert_eq!(clean[0], "  keep  ");
    assert_eq!(clean[1], "é".repeat(4000));
    assert_eq!(clean[98], "96");
}

#[tokio::test]
#[ignore = "requires isolated MongoDB, frontend node_modules and PORTHUB_TEST_NODE_REALTIME=1"]
async fn official_frontend_client_uses_native_status_and_log_events() -> Result<()> {
    if std::env::var("PORTHUB_TEST_NODE_REALTIME").as_deref() != Ok("1") {
        return Ok(());
    }
    let case = Case::new(Config::default()).await?;
    let (address, task) = serving(&case).await?;
    let result=async {
        let (owner,cookie)=case.user("node-owner@test.invalid","user").await?;let id=ObjectId::new();
        case.app.collection("machines").insert_one(doc! {"_id":id,"user_id":owner,"name":"Native SDK","token":"sdk-secret","enabled":true}).await?;
        let script=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ui/tests/native-realtime.cjs");
        let child=tokio::process::Command::new("node").arg(script)
            .env("PORTHUB_TEST_SOCKET_URL",format!("http://{address}"))
            .env("PORTHUB_TEST_SESSION_COOKIE",cookie).env("PORTHUB_TEST_MACHINE_ID",id.to_hex()).env("PORTHUB_TEST_MACHINE_TOKEN","sdk-secret")
            .kill_on_drop(true).output();
        let output=tokio::time::timeout(Duration::from_secs(15),child).await??;
        ensure!(output.status.success(),"official client failed: {}",String::from_utf8_lossy(&output.stderr));
        ensure!(String::from_utf8_lossy(&output.stdout).contains("Native Socket.IO status and log streaming passed."));
        Ok(())
    }.await;
    case.app.realtime.close().await;
    task.abort();
    let _ = task.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn legacy_sync_preserves_top_level_response_and_disabled_configuration() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result=async {
        let id=ObjectId::new();
        case.app.collection("machines").insert_one(doc! {"_id":id,"name":"Legacy","token":"legacy-secret","enabled":false,
            "hostname_override":"fixed-host","client_hostname":"previous","client_version":"original-version","client_update_request_id":"pending-request"}).await?;
        let body=json!({"machine_id":id.to_hex(),"token":"legacy-secret","hostname":" new-runtime ","local_ip":" 192.168.1.9 ",
            "public_ip":"198.51.100.7","is_active":true,"client_version":{},"client_update_last_handled_request_id":[]});
        let (status,headers,result)=case.call("POST","/api/machines/sync","",body.clone(),&[]).await?;
        ensure!(status==StatusCode::OK && result["msg"]=="Machine synced successfully");
        ensure!(result["data"]["_id"]==id.to_hex() && result["data"]["hostname"]=="fixed-host" && result["data"]["enabled"]==false);
        ensure!(result["config"]["machine_id"]==id.to_hex() && result["config"]["enabled"]==false && result["endpoints"].is_object());
        ensure!(headers["x-porthub-observed-ip"]=="198.51.100.7");
        let stored=case.app.collection("machines").find_one(doc! {"_id":id}).await?.unwrap();
        ensure!(stored.get_str("client_hostname")?=="new-runtime" && stored.get_str("client_version")?=="original-version" && !stored.contains_key("client_update_last_handled_request_id"));
        let mut wrong=body.clone();wrong["token"]=json!("wrong");
        case.status("POST","/api/machines/sync","",wrong,StatusCode::UNAUTHORIZED).await?;
        case.app.collection("machines").update_one(doc! {"_id":id},doc! {"$set":{"deletion_pending":true}}).await?;
        let (status,headers,_)=case.call("POST","/api/machines/sync","",body,&[]).await?;
        ensure!(status==StatusCode::GONE && headers["x-porthub-machine-deleted"]=="true");
        Ok(())
    }.await;
    case.app.realtime.close().await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn revoked_and_expired_sessions_are_revalidated_before_outgoing_data() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let (address, task) = serving(&case).await?;
    let result=async {
        let (owner,cookie)=case.user("session-owner@test.invalid","user").await?;let id=ObjectId::new();
        let machine=doc! {"_id":id,"user_id":owner,"name":"Luna","token":"post-revocation-secret","enabled":true};
        case.app.collection("machines").insert_one(&machine).await?;
        let (mut browser,accepted)=Wire::open(address,&cookie,json!({}),None).await?;ensure!(accepted);
        browser.emit(CTS_SUBSCRIBE,Some(json!({"machine_id":id.to_hex()}))).await?;browser.expect(STC_LOG_STATUS).await?;
        let session=cookie.split_once('=').unwrap().1;
        case.app.collection("user_sessions").update_one(doc! {"_id":session},doc! {"$set":{"revoked_at":DateTime::now()}}).await?;
        case.app.notify_status(&machine).await;
        browser.disconnected(Some("post-revocation-secret")).await?;
        ensure!(!case.app.realtime.log_requested(&case.app,&id.to_hex()).await.map_err(api_error)?);
        let (rejected,accepted)=Wire::open(address,&cookie,json!({}),None).await?;ensure!(!accepted);rejected.close().await;
        let (_,cookie)=case.user("expired-owner@test.invalid","user").await?;
        let session=cookie.split_once('=').unwrap().1;
        let (mut expired,accepted)=Wire::open(address,&cookie,json!({}),None).await?;ensure!(accepted);
        case.app.collection("user_sessions").update_one(doc! {"_id":session},doc! {"$set":{"expires_at":DateTime::from_millis(0)}}).await?;
        expired.emit(CTS_STATUS,None).await?;expired.disconnected(None).await?;
        browser.close().await;expired.close().await;
        Ok(())
    }.await;
    case.app.realtime.close().await;
    task.abort();
    let _ = task.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn temporary_port_create_close_and_expiry_notify_only_the_owner_without_agent_socket() -> Result<()> {
    let case = Case::new(Config { service_domain: "services.example.invalid".into(), external_port_range: Some((31000,31002)), ..Default::default() }).await?;
    let (address, task) = serving(&case).await?;
    let result = async {
        let (owner, cookie) = case.user("exposure-events@test.invalid", "user").await?;
        let (_, foreign_cookie) = case.user("other-exposure-events@test.invalid", "user").await?;
        let id = ObjectId::new();
        case.app.collection("machines").insert_one(doc! {"_id":id,"user_id":owner,"name":"Fixture","enabled":true,"token":"fixture-token"}).await?;
        let (mut browser, accepted) = Wire::open(address, &cookie, json!({}), None).await?; ensure!(accepted);
        let (mut outsider, accepted) = Wire::open(address, &foreign_cookie, json!({}), None).await?; ensure!(accepted);
        for expire in [false,true] {
            let created = case.status("POST", "/api/machines/client/expose", "", json!({"machine_id":id.to_hex(),"token":"fixture-token","request_id":uuid::Uuid::new_v4().simple().to_string(),"local_port":8000}), StatusCode::OK).await?;
            ensure!(browser.expect(STC_CONNECTIONS_CHANGED).await? == json!({"machine_id":id.to_hex()}));
            outsider.quiet().await?;
            let exposure = created["data"]["exposure_id"].as_str().context("exposure id")?;
            if expire {
                case.app.collection("connections").update_one(doc! {"exposure_id":exposure},doc! {"$set":{"lease_expires_at":DateTime::from_millis(0)}}).await?;
                porthub_api::routes::exposes::recover_due(&case.app).await.map_err(api_error)?;
            } else {
                case.status("POST", "/api/machines/client/expose/close", "", json!({"machine_id":id.to_hex(),"token":"fixture-token","exposure_id":exposure}), StatusCode::OK).await?;
            }
            ensure!(browser.expect(STC_CONNECTIONS_CHANGED).await? == json!({"machine_id":id.to_hex()}));
            outsider.quiet().await?;
        }
        browser.close().await; outsider.close().await;
        Ok(())
    }.await;
    case.app.realtime.close().await; task.abort(); case.db.drop().await?;
    result
}
