use anyhow::{ensure, Context, Result};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::put,
    Json, Router,
};
use mongodb::bson::{doc, oid::ObjectId};
use porthub_api::{config::Config, generated};
use porthub_tunnel::{gateway_config, EmbeddedClient, EmbeddedServer};
use serde_json::{json, Value};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::RwLock,
    task::JoinSet,
};
mod support;
use support::Case;

#[tokio::test]
async fn ipc_client_rejects_wrong_receipts_large_bodies_errors_and_redirects() -> Result<()> {
    use axum::{
        response::IntoResponse,
        routing::{get, post},
    };
    use porthub_runtime::gateway_apply::{digest, Snapshot};
    let temporary = tempfile::tempdir()?;
    let socket = temporary.path().join("edge.sock");
    let (listener, _lease) = porthub_runtime::socket::bind(&socket).await?;
    let mode = Arc::new(Mutex::new("ok"));
    let followed = Arc::new(AtomicUsize::new(0));
    let observed = followed.clone();
    let router =
        Router::new()
            .route(
                "/apply",
                post(
                    |State(mode): State<Arc<Mutex<&'static str>>>,
                     Json(request): Json<Snapshot>| async move {
                        match *mode.lock().unwrap() {
                            "wrong" => Json(json!({"digest":"0".repeat(64)})).into_response(),
                            "extra" => {
                                Json(json!({"digest":request.digest,"extra":true})).into_response()
                            }
                            "huge" => "x".repeat(2048).into_response(),
                            "error" => StatusCode::SERVICE_UNAVAILABLE.into_response(),
                            "redirect" => {
                                (StatusCode::FOUND, [("location", "/unexpected")]).into_response()
                            }
                            _ => Json(request).into_response(),
                        }
                    },
                ),
            )
            .route(
                "/unexpected",
                get(move || {
                    let observed = observed.clone();
                    async move {
                        observed.fetch_add(1, Ordering::SeqCst);
                        StatusCode::OK
                    }
                }),
            )
            .with_state(mode.clone());
    let task = tokio::spawn(async move { axum::serve(listener, router).await });
    let result = async {
        let client = porthub_api::gateway_apply::Client::new(&socket)?;
        let expected = digest(b"[server.services]\n");
        client
            .apply(&expected)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e.detail))?;
        for fault in ["wrong", "extra", "huge", "error", "redirect"] {
            *mode.lock().unwrap() = fault;
            let error = client
                .apply(&expected)
                .await
                .err()
                .context("invalid acknowledgement accepted")?;
            ensure!(error.status == StatusCode::BAD_GATEWAY);
        }
        ensure!(followed.load(Ordering::SeqCst) == 0);
        Ok(())
    }
    .await;
    task.abort();
    let _ = task.await;
    result
}

struct Firewall {
    public: SocketAddr,
    policy: Mutex<Option<Value>>,
    closed: AtomicUsize,
    fail_delete: AtomicBool,
}
async fn save(
    State(state): State<Arc<Firewall>>,
    headers: HeaderMap,
    Json(value): Json<Value>,
) -> (StatusCode, Json<Value>) {
    assert_eq!(headers["x-api-key"], "apply-test-key");
    // Restriction installation must precede new listener publication.
    if state.policy.lock().unwrap().is_none() {
        assert!(TcpStream::connect(state.public).await.is_err());
    }
    *state.policy.lock().unwrap() = Some(value);
    (StatusCode::OK, Json(json!({"data":{}})))
}
async fn remove(
    State(state): State<Arc<Firewall>>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    assert_eq!(headers["x-api-key"], "apply-test-key");
    assert!(
        TcpStream::connect(state.public).await.is_err(),
        "firewall cleanup raced a live listener"
    );
    let rebound = TcpListener::bind(state.public).await.unwrap();
    drop(rebound);
    if state.fail_delete.swap(false, Ordering::SeqCst) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"detail":"test firewall failure"})),
        );
    }
    state.closed.fetch_add(1, Ordering::SeqCst);
    *state.policy.lock().unwrap() = None;
    (StatusCode::OK, Json(json!({"data":{}})))
}
async fn exchange(stream: &mut TcpStream) -> Result<()> {
    let payload = vec![73; 256 * 1024];
    stream.write_all(&payload).await?;
    let mut actual = vec![0; payload.len()];
    stream.read_exact(&mut actual).await?;
    ensure!(actual == payload);
    Ok(())
}
async fn ready(address: SocketAddr) -> Result<TcpStream> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(mut stream) = TcpStream::connect(address).await {
                if exchange(&mut stream).await.is_ok() {
                    return Ok(stream);
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn native_api_waits_for_live_listener_and_forward_closure_before_policy_cleanup() -> Result<()>
{
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("gateway.toml");
    let socket = temporary.path().join("edge.sock");
    let fw_socket = temporary.path().join("firewall.sock");
    std::fs::write(&path, "[server.services]\n")?;
    let public = TcpListener::bind("127.0.0.1:0").await?.local_addr()?;
    let firewall = Arc::new(Firewall {
        public,
        policy: Mutex::new(None),
        closed: AtomicUsize::new(0),
        fail_delete: AtomicBool::new(false),
    });
    let mut workers = JoinSet::new();
    let (fw, _fw_lease) = porthub_runtime::socket::bind(&fw_socket).await?;
    let mock = Router::new()
        .route("/api/ports/{port}/policy", put(save).delete(remove))
        .with_state(firewall.clone());
    workers.spawn(async move {
        let _ = axum::serve(fw, mock).await;
    });
    let server = Arc::new(RwLock::new(
        EmbeddedServer::new(gateway_config("[server.services]\n")?).await?,
    ));
    let (listener, _edge_lease) = porthub_runtime::socket::bind(&socket).await?;
    let apply = porthub_edge::apply::router(server.clone(), path.clone());
    let mut control = Some(tokio::spawn(
        async move { axum::serve(listener, apply).await },
    ));
    let http = TcpListener::bind("127.0.0.1:0").await?;
    let address = http.local_addr()?;
    let router = porthub_edge::router(server.clone());
    workers.spawn(async move {
        let _ = axum::serve(http, router).await;
    });
    let local = TcpListener::bind("127.0.0.1:0").await?;
    let target = local.local_addr()?;
    workers.spawn(async move {
        let mut copies = JoinSet::new();
        loop {
            while copies.try_join_next().is_some() {}
            let Ok((stream, _)) = local.accept().await else {
                break;
            };
            copies.spawn(async move {
                let (mut read, mut write) = stream.into_split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    let case = Case::new(Config {
        gateway_config_path: Some(path.clone()),
        edge_socket: Some(socket.clone()),
        firewall_socket: Some(fw_socket),
        firewall_api_key: "apply-test-key".into(),
        ..Default::default()
    })
    .await?;
    let result=async {
        let (owner,cookie)=case.user("apply-owner@test.invalid","user").await?;
        let machine=ObjectId::new();let connection=ObjectId::new();
        case.app.collection("machines").insert_one(doc! {"_id":machine,"user_id":owner,"name":"Luna","enabled":true,"token":"fixture-secret"}).await?;
        let record=doc! {"_id":connection,"user_id":owner,"machine_id":machine,"external_port":i32::from(public.port()),
            "internal_port":i32::from(target.port()),"internal_ip":"127.0.0.1","enabled":true,"firewall":{"is_public":false,"allowed_ips":["203.0.113.9"]}};
        case.app.collection("connections").insert_one(&record).await?;
        // Prime never removes stale policies or requires a running edge.
        porthub_api::firewall::prime(&case.app).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
        generated::rebuild(&case.app).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
        let key=generated::service_key(&record);
        let text=format!("[client]\nremote_addr=\"{address}\"\nretry_interval=1\n[client.transport]\ntype=\"websocket\"\n[client.transport.websocket]\ntls=false\npath=\"/api/tunnel\"\nporthub_framing=true\nhttp_upgrade=true\n[client.services.{key}]\ntoken=\"fixture-secret\"\nlocal_addr=\"{target}\"\n");
        let agent=EmbeddedClient::new(porthub_tunnel::Config::from_str(&text)?).await?;
        let mut stream=ready(public).await?;
        // A failed/missing acknowledgement cannot authorize removing a rule.
        let task=control.take().unwrap();task.abort();let _=task.await;
        let response=case.status("PUT","/api/machines/update",&cookie,json!({"data_id":machine.to_hex(),"name":"Luna","enabled":false}),StatusCode::BAD_GATEWAY).await?;
        ensure!(response["detail"]=="Gateway apply request failed");
        ensure!(firewall.closed.load(Ordering::SeqCst)==0 && firewall.policy.lock().unwrap().is_some());
        ensure!(case.app.collection("machines").find_one(doc! {"_id":machine}).await?.context("machine")?.get_bool("enabled")?);
        exchange(&mut stream).await?;
        case.status("POST","/api/machines/delete",&cookie,json!({"data_id":machine.to_hex()}),StatusCode::BAD_GATEWAY).await?;
        let restored=case.app.collection("machines").find_one(doc! {"_id":machine}).await?.context("restored machine")?;
        ensure!(restored.get_bool("enabled")? && !restored.contains_key("native_deletion") && !restored.contains_key("deletion_pending"));
        ensure!(firewall.closed.load(Ordering::SeqCst)==0 && firewall.policy.lock().unwrap().is_some());
        exchange(&mut stream).await?;
        // Restore only this test's endpoint. Successful apply now waits until
        // the old visitor and listening socket are both closed.
        drop(_edge_lease);
        let (listener,_new_lease)=porthub_runtime::socket::bind(&socket).await?;
        let apply=porthub_edge::apply::router(server.clone(),path.clone());
        workers.spawn(async move {let _=axum::serve(listener,apply).await;});
        case.status("PUT","/api/machines/update",&cookie,json!({"data_id":machine.to_hex(),"name":"Luna","enabled":false}),StatusCode::OK).await?;
        ensure!(firewall.closed.load(Ordering::SeqCst)==1 && firewall.policy.lock().unwrap().is_none());
        ensure!(!matches!(stream.read(&mut [0]).await,Ok(n) if n>0));
        case.status("PUT","/api/machines/update",&cookie,json!({"data_id":machine.to_hex(),"name":"Luna","enabled":true}),StatusCode::OK).await?;
        let mut stream=ready(public).await?;
        case.status("POST","/api/connections/delete",&cookie,json!({"data_id":connection.to_hex()}),StatusCode::OK).await?;
        ensure!(firewall.closed.load(Ordering::SeqCst)==2);
        ensure!(!matches!(stream.read(&mut [0]).await,Ok(n) if n>0));
        ensure!(case.app.collection("connections").find_one(doc! {"_id":connection}).await?.is_none());
        // Recreate this fixture mapping and exercise whole-machine retirement.
        case.app.collection("connections").insert_one(&record).await?;
        porthub_api::firewall::prime(&case.app).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
        generated::rebuild(&case.app).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
        let mut stream=ready(public).await?;
        firewall.fail_delete.store(true,Ordering::SeqCst);
        case.status("POST","/api/machines/delete",&cookie,json!({"data_id":machine.to_hex()}),StatusCode::BAD_GATEWAY).await?;
        let restored=case.app.collection("machines").find_one(doc! {"_id":machine}).await?.context("restored machine")?;
        ensure!(restored.get_bool("enabled")? && !restored.contains_key("deletion_pending") && !restored.contains_key("native_deletion"));
        ensure!(firewall.closed.load(Ordering::SeqCst)==2 && firewall.policy.lock().unwrap().is_some());
        ensure!(!matches!(stream.read(&mut [0]).await,Ok(n) if n>0));
        let mut stream=ready(public).await?;
        case.status("POST","/api/machines/delete",&cookie,json!({"data_id":machine.to_hex()}),StatusCode::OK).await?;
        ensure!(firewall.closed.load(Ordering::SeqCst)==3 && firewall.policy.lock().unwrap().is_none());
        ensure!(!matches!(stream.read(&mut [0]).await,Ok(n) if n>0));
        ensure!(case.app.collection("connections").find_one(doc! {"_id":connection}).await?.is_none());
        ensure!(case.app.collection("machines").find_one(doc! {"_id":machine}).await?.context("tombstone")?.get_bool("deletion_pending")?);
        let acknowledged=case.status("POST","/api/machines/client/deletion-ack","",json!({"machine_id":machine.to_hex(),"token":"fixture-secret"}),StatusCode::OK).await?;
        ensure!(acknowledged["data"]["removed"]==true);
        agent.shutdown().await;
        Ok(())
    }.await;
    if let Some(task) = control.take() {
        task.abort();
        let _ = task.await;
    }
    server.write().await.shutdown().await;
    workers.shutdown().await;
    case.db.drop().await?;
    result
}
