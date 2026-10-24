#![cfg(unix)]
mod common;
use anyhow::{ensure, Context, Result};
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use porthub_agent::{
    profile::Profile,
    runtime::{self, Options},
};
use porthub_tunnel::{gateway_config, EmbeddedServer};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::RwLock,
};
use tokio_util::sync::CancellationToken;
const MACHINE: &str = "0123456789abcdef01234567";
const TOKEN: &str = "secret-machine-runtime-token";
#[derive(Clone)]
struct Snapshot {
    text: String,
    version: String,
    disabled: bool,
    deleted: bool,
    machine: String,
}
struct Control {
    snapshot: Mutex<Snapshot>,
    syncs: AtomicUsize,
    acks: AtomicUsize,
}
async fn sync(State(state): State<Arc<Control>>, Json(body): Json<Value>) -> Response {
    assert_eq!(body["machine_id"], MACHINE);
    assert_eq!(body["token"], TOKEN);
    assert_eq!(body["client_version"], porthub_agent::VERSION);
    assert!(body["hostname"].as_str().is_some_and(|v| !v.is_empty()));
    state.syncs.fetch_add(1, Ordering::SeqCst);
    let snapshot = state.snapshot.lock().unwrap().clone();
    if snapshot.deleted {
        return StatusCode::GONE.into_response();
    }
    if snapshot.disabled {
        return StatusCode::FORBIDDEN.into_response();
    }
    Json(json!({"data":{"config":{"machine_id":snapshot.machine,"version":snapshot.version,"files":{"client.toml":snapshot.text}}}})).into_response()
}
async fn changes(
    State(state): State<Arc<Control>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    assert_eq!(query.get("machine_id").map(String::as_str), Some(MACHINE));
    assert_eq!(query.get("token").map(String::as_str), Some(TOKEN));
    tokio::time::sleep(Duration::from_millis(50)).await;
    let snapshot = state.snapshot.lock().unwrap().clone();
    if snapshot.deleted {
        return StatusCode::GONE.into_response();
    }
    if snapshot.disabled {
        return StatusCode::FORBIDDEN.into_response();
    }
    let mut headers = HeaderMap::new();
    headers.insert("x-porthub-machine-id", snapshot.machine.parse().unwrap());
    headers.insert(
        "x-porthub-config-version",
        snapshot.version.parse().unwrap(),
    );
    if query.get("since") == Some(&snapshot.version) {
        (StatusCode::NO_CONTENT, headers).into_response()
    } else {
        (headers, snapshot.text).into_response()
    }
}
async fn ack(State(state): State<Arc<Control>>, Json(body): Json<Value>) -> Json<Value> {
    assert_eq!(body["token"], TOKEN);
    state.acks.fetch_add(1, Ordering::SeqCst);
    Json(json!({"data":{"removed":true}}))
}
async fn status(path: &Path, wanted: &str) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if runtime::status(path).is_ok_and(|status| status.state == wanted) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    Ok(())
}
async fn connected(address: std::net::SocketAddr) -> Result<TcpStream> {
    Ok(tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(mut stream) = TcpStream::connect(address).await {
                let probe = async {
                    stream.write_all(b"\x7f").await?;
                    let mut byte = [0];
                    stream.read_exact(&mut byte).await?;
                    Ok::<bool, std::io::Error>(byte == [0x7f])
                };
                if matches!(
                    tokio::time::timeout(Duration::from_millis(200), probe).await,
                    Ok(Ok(true))
                ) {
                    break stream;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?)
}

async fn echo(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
    stream.write_all(payload).await?;
    let mut data = vec![0; payload.len()];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut data)).await??;
    ensure!(data == payload);
    Ok(())
}
async fn closed(stream: &mut TcpStream) -> Result<()> {
    let mut byte = [0];
    match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte)).await? {
        Ok(0) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
            ) =>
        {
            Ok(())
        }
        other => anyhow::bail!("revoked stream remained open: {other:?}"),
    }
}

async fn selected(path: &Path, route: &str, state: Option<&str>) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            if runtime::status(path).is_ok_and(|status| {
                status.route == route && state.is_none_or(|state| status.state == state)
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn scheduled_origin_failover_and_recovery_preserve_transfers_even_during_api_backoff(
) -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local = listener.local_addr()?;
    let echo_server = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut input, mut output) = stream.split();
                let _ = tokio::io::copy(&mut input, &mut output).await;
            });
        }
    });
    let reservation = TcpListener::bind("127.0.0.1:0").await?;
    let public = reservation.local_addr()?;
    drop(reservation);
    let gateway = Arc::new(RwLock::new(
        EmbeddedServer::new(gateway_config(&format!(
            "[server.services.echo]\nbind_addr='{public}'\ntoken='{TOKEN}'\n"
        ))?)
        .await?,
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_address = listener.local_addr()?;
    let router = porthub_edge::router(gateway.clone());
    let mut proxy = tokio::spawn(async move { axum::serve(listener, router).await });
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let origin_address = listener.local_addr()?;
    let router = porthub_edge::router(gateway.clone());
    let mut origin = tokio::spawn(async move { axum::serve(listener, router).await });
    let config = format!(
        "[client]\nremote_addr='ws://{proxy_address}/api/tunnel'\n\
         direct_addr='http://{origin_address}/api/tunnel'\n\
         [client.services.echo]\nlocal_addr='{local}'\ntoken='{TOKEN}'\n"
    );
    let state = Arc::new(Control {
        snapshot: Mutex::new(Snapshot {
            text: config,
            version: "stable".into(),
            disabled: false,
            deleted: false,
            machine: MACHINE.into(),
        }),
        syncs: AtomicUsize::new(0),
        acks: AtomicUsize::new(0),
    });
    let router = Router::new()
        .route("/api/machines/client/sync", post(sync))
        .route("/api/machines/client/changes.toml", get(changes))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server = format!("http://{}", listener.local_addr()?);
    let api = tokio::spawn(async move { axum::serve(listener, router).await });
    let directory = common::private_dir()?;
    let path = directory.path().join("machine.json");
    Profile {
        format_version: 1,
        server,
        machine_id: MACHINE.into(),
        token: TOKEN.into(),
        setup_overrides: Default::default(),
        fallback_servers: Vec::new(),
        allow_insecure_http_for_tests: true,
    }
    .save_new(&path)?;
    let cancel = CancellationToken::new();
    let worker = tokio::spawn(runtime::run(
        path.clone(),
        cancel.clone(),
        Options {
            heartbeat: Duration::from_millis(150),
            retry: Duration::from_secs(5),
            probe_timeout: Duration::from_millis(100),
        },
    ));
    let result = tokio::time::timeout(Duration::from_secs(20), async {
        selected(&path, "origin", Some("running")).await?;
        let mut first = connected(public).await?;
        origin.abort();
        let _ = (&mut origin).await;
        selected(&path, "primary", Some("running")).await?;
        let mut second = connected(public).await?;
        let payload = vec![0x5a; 1024 * 1024];
        echo(&mut first, &payload).await?;
        echo(&mut second, &payload).await?;
        let listener = TcpListener::bind(origin_address).await?;
        let router = porthub_edge::router(gateway.clone());
        origin = tokio::spawn(async move { axum::serve(listener, router).await });
        selected(&path, "origin", Some("running")).await?;
        let mut third = connected(public).await?;
        echo(&mut first, &payload).await?;
        echo(&mut second, &payload).await?;
        echo(&mut third, &payload).await?;
        // With no verified replacement, keep the existing selection and its
        // live copies rather than blindly choosing the unavailable primary.
        proxy.abort();
        let _ = (&mut proxy).await;
        origin.abort();
        let _ = (&mut origin).await;
        tokio::time::sleep(Duration::from_millis(650)).await;
        ensure!(runtime::status(&path)?.route == "origin");
        echo(&mut first, &payload).await?;
        echo(&mut second, &payload).await?;
        let listener = TcpListener::bind(proxy_address).await?;
        let router = porthub_edge::router(gateway.clone());
        proxy = tokio::spawn(async move { axum::serve(listener, router).await });
        // API retry sleeps must not suspend independent endpoint recovery.
        api.abort();
        origin.abort();
        selected(&path, "primary", Some("gateway-unavailable")).await?;
        let mut fourth = connected(public).await?;
        echo(&mut fourth, &payload).await?;
        echo(&mut first, &payload).await?;
        ensure!(runtime::status(&path)?.config_version == "stable");
        anyhow::Ok(())
    })
    .await;
    cancel.cancel();
    let stopped = worker.await?;
    origin.abort();
    proxy.abort();
    api.abort();
    echo_server.abort();
    gateway.write().await.shutdown().await;
    stopped?;
    result??;
    Ok(())
}
#[tokio::test]
async fn saved_profile_syncs_reload_in_place_and_revoke_without_a_helper_process() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(30),async {
        let target=TcpListener::bind("127.0.0.1:0").await?;let local=target.local_addr()?;
        let echo_server=tokio::spawn(async move{let mut children=tokio::task::JoinSet::new();loop{tokio::select!{stream=target.accept()=>{let(mut stream,_)=stream.unwrap();children.spawn(async move{let(mut read,mut write)=stream.split();let _=tokio::io::copy(&mut read,&mut write).await;});},_=children.join_next(),if !children.is_empty()=>{}}}});
        let port=TcpListener::bind("127.0.0.1:0").await?;let public=port.local_addr()?;drop(port);
        let gateway=Arc::new(RwLock::new(EmbeddedServer::new(gateway_config(&format!("[server.services.echo]\ntoken='{TOKEN}'\nbind_addr='{public}'\n"))?).await?));
        let listener=TcpListener::bind("127.0.0.1:0").await?;let gateway_address=listener.local_addr()?;let edge_router=porthub_edge::router(gateway.clone());
        let edge=tokio::spawn(async move{axum::serve(listener,edge_router).await});
        let config=format!("[client]\nremote_addr='ws://{gateway_address}/api/tunnel'\n[client.services.echo]\ntoken='{TOKEN}'\nlocal_addr='{local}'\n");
        let state=Arc::new(Control{snapshot:Mutex::new(Snapshot{text:config.clone(),version:"v1".into(),disabled:false,deleted:false,machine:MACHINE.into()}),syncs:AtomicUsize::new(0),acks:AtomicUsize::new(0)});
        let router=Router::new().route("/api/machines/client/sync",post(sync)).route("/api/machines/client/changes.toml",get(changes)).route("/api/machines/client/deletion-ack",post(ack)).with_state(state.clone());
        let listener=TcpListener::bind("127.0.0.1:0").await?;let server=format!("http://{}",listener.local_addr()?);let api=tokio::spawn(async move{axum::serve(listener,router).await});
        let directory=common::private_dir()?;let path=directory.path().join("machine.json");
        Profile{format_version:1,server,machine_id:MACHINE.into(),token:TOKEN.into(),setup_overrides: Default::default(), fallback_servers:Vec::new(),allow_insecure_http_for_tests:true}.save_new(&path)?;
        let cancel=CancellationToken::new();let worker=tokio::spawn(runtime::run(path.clone(),cancel.clone(),Options{heartbeat:Duration::from_secs(1),retry:Duration::from_millis(30),probe_timeout:Duration::from_millis(100)}));
        status(&path,"running").await?;ensure!(runtime::run(path.clone(),CancellationToken::new(),Options::default()).await.is_err(),"duplicate profile owner accepted");
        let mut stream=connected(public).await?;let payload:Vec<u8>=(0..1024*1024).map(|i|(i%251)as u8).collect();echo(&mut stream,&payload).await.context("initial payload")?;
        state.snapshot.lock().unwrap().version="v2".into();tokio::time::sleep(Duration::from_millis(1200)).await;echo(&mut stream,b"unchanged sessions survive sync and version changes").await.context("unchanged sessions survive sync and version changes")?;
        ensure!(runtime::status(&path)?.config_version=="v2");ensure!(state.syncs.load(Ordering::SeqCst)>=2);
        {let mut snapshot=state.snapshot.lock().unwrap();snapshot.machine="ffffffffffffffffffffffff".into();snapshot.version="v3".into();}
        status(&path,"configuration-rejected").await?;echo(&mut stream,b"wrong-machine response must not replace live forwarding").await.context("wrong-machine response must not replace live forwarding")?;
        {let mut snapshot=state.snapshot.lock().unwrap();snapshot.machine=MACHINE.into();snapshot.disabled=true;}
        status(&path,"authorization-required").await?;closed(&mut stream).await?;
        state.snapshot.lock().unwrap().disabled=false;status(&path,"running").await?;let mut stream=connected(public).await?;echo(&mut stream,b"forwarding resumes after re-enable").await.context("forwarding resumes after re-enable")?;
        {let mut snapshot=state.snapshot.lock().unwrap();snapshot.version="v4".into();snapshot.text=format!("[client]\nremote_addr='ws://{gateway_address}/api/tunnel'\n");}
        tokio::time::timeout(Duration::from_secs(5),async{loop{if runtime::status(&path).is_ok_and(|status|status.config_version=="v4"&&status.service_count==0){break;}tokio::time::sleep(Duration::from_millis(10)).await;}}).await?;
        closed(&mut stream).await?;
        {let mut snapshot=state.snapshot.lock().unwrap();snapshot.version="v5".into();snapshot.text=config;}
        let mut stream=connected(public).await?;echo(&mut stream,b"service added again through native synchronization").await.context("service added again through native synchronization")?;
        state.snapshot.lock().unwrap().deleted=true;worker.await??;ensure!(runtime::status(&path)?.state=="deleted"&&state.acks.load(Ordering::SeqCst)==1);closed(&mut stream).await?;
        let status=std::fs::read_to_string(porthub_agent::profile::sibling(&path,".status.json"))?;ensure!(!status.contains(TOKEN)&&!status.contains(&gateway_address.to_string()));
        ensure!(Profile::load(&path)?.machine_id==MACHINE);edge.abort();api.abort();echo_server.abort();gateway.write().await.shutdown().await;Ok::<(),anyhow::Error>(())
    }).await.context("native profile runtime timed out")?
}
#[tokio::test]
async fn control_fallback_retries_network_failure_but_not_authorization_rejection() -> Result<()> {
    use porthub_agent::control::{Control, Failure};
    let fallback_calls = Arc::new(AtomicUsize::new(0));
    let calls = fallback_calls.clone();
    let fallback = Router::new().fallback(move || {
        let calls = calls.clone();
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            Json(json!({"data":{}}))
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let fallback_url = format!("http://{}", listener.local_addr()?);
    let fallback_task = tokio::spawn(async move { axum::serve(listener, fallback).await });
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let primary = format!("http://{}", listener.local_addr()?);
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(|| async { StatusCode::FORBIDDEN }),
        )
        .await
    });
    let profile = Profile {
        format_version: 1,
        server: primary,
        machine_id: MACHINE.into(),
        token: TOKEN.into(),
        setup_overrides: Default::default(),
        fallback_servers: vec![fallback_url],
        allow_insecure_http_for_tests: true,
    };
    let control = Control::new(profile)?;
    ensure!(matches!(
        control.sync("test-host", "").await,
        Err(Failure::Rejected(403))
    ));
    ensure!(fallback_calls.load(Ordering::SeqCst) == 0);
    task.abort();
    control.sync("test-host", "").await?;
    ensure!(fallback_calls.load(Ordering::SeqCst) == 1);
    let error = Failure::Rejected(403).to_string();
    ensure!(!error.contains(TOKEN));
    fallback_task.abort();
    Ok(())
}

#[tokio::test]
async fn control_redirects_cannot_send_machine_credentials_to_an_unconfigured_endpoint(
) -> Result<()> {
    use porthub_agent::control::Control;
    let leaked = Arc::new(AtomicUsize::new(0));
    let captured = leaked.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let unconfigured = format!("http://{}/leak", listener.local_addr()?);
    let target = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(move || {
                let captured = captured.clone();
                async move {
                    captured.fetch_add(1, Ordering::SeqCst);
                    Json(json!({"data":{}}))
                }
            }),
        )
        .await
    });
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let fallback = format!("http://{}", listener.local_addr()?);
    let fallback_task = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(|| async { Json(json!({"data":{}})) }),
        )
        .await
    });
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let primary = format!("http://{}", listener.local_addr()?);
    let redirect = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(move || {
                let location = unconfigured.clone();
                async move { (StatusCode::TEMPORARY_REDIRECT, [("location", location)]) }
            }),
        )
        .await
    });
    let profile = Profile {
        format_version: 1,
        server: primary,
        machine_id: MACHINE.into(),
        token: TOKEN.into(),
        setup_overrides: Default::default(),
        fallback_servers: vec![fallback],
        allow_insecure_http_for_tests: true,
    };
    Control::new(profile)?.sync("fixture", "").await?;
    ensure!(leaked.load(Ordering::SeqCst) == 0);
    redirect.abort();
    target.abort();
    fallback_task.abort();
    Ok(())
}
