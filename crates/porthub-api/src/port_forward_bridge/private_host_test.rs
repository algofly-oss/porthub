//! Private HTTP over a real OpenSSH remote-dynamic session. The database,
//! exporter sockets, control HTTP server and broker are isolated per test.
use super::*;
use crate::domain::workspaces::token_digest;
use axum::body::to_bytes;
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};
use porthub_forward_ssh::Master;
use std::{os::unix::fs::PermissionsExt, process::Stdio};
use tokio::{
    net::{TcpListener, UnixStream},
    process::Command,
    time::timeout,
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, Message as Frame},
};
use tokio_util::task::AbortOnDropHandle;

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
#[ignore = "requires isolated MongoDB and OpenSSH"]
async fn open_ssh_host_private_http_and_live_audience_revocation() -> Result<()> {
    let db = mongodb::Client::with_uri_str(std::env::var("PORTHUB_TEST_MONGO_URI")?)
        .await?
        .database(&format!(
            "porthub_ssh_host_e2e_{}",
            uuid::Uuid::new_v4().simple()
        ));
    let edge_dir = tempfile::tempdir()?;
    let edge_path = edge_dir.path().join("edge.sock");
    let socket = tokio::net::UnixListener::bind(&edge_path)?;
    let server =
        porthub_tunnel::EmbeddedServer::new(porthub_tunnel::gateway_config("[server.services]")?)
            .await?;
    let edge = porthub_edge::apply::router(
        Arc::new(tokio::sync::RwLock::new(server)),
        edge_dir.path().join("edge.toml"),
    );
    let _edge =
        AbortOnDropHandle::new(tokio::spawn(async move { axum::serve(socket, edge).await }));
    let app = Arc::new(App::new(
        crate::config::Config {
            edge_socket: Some(edge_path),
            private_relay_tls_origin: Some("https://127.0.0.1:8243".into()),
            ..Default::default()
        },
        db.clone(),
    ));
    let result = timeout(Duration::from_secs(30), exercise(app)).await;
    db.drop().await?;
    result?
}

async fn exercise(app: Arc<App>) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (owner, machine, id) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
    let master = Master::open(&dir.path().join("master"))?;
    let (pem, key) = master.credentials(&owner.to_hex(), &id.to_hex())?;
    let host_key = master.host_public_key()?;
    app.forward_keys
        .set(master)
        .map_err(|_| anyhow!("unexpected SSH key initialization"))?;
    let identity = dir.path().join("identity");
    std::fs::write(&identity, pem.as_bytes())?;
    std::fs::set_permissions(&identity, std::fs::Permissions::from_mode(0o600))?;
    let token = "isolated-forward-test";
    let hash = token_digest(token);
    let peer = format!("{owner}:{machine}");
    let instance = "test-consumer";
    app.collection("users")
        .insert_one(doc! {"_id":owner})
        .await?;
    app.collection("machines")
        .insert_one(doc! {"_id":machine,"user_id":owner})
        .await?;
    app.collection("private_peers")
        .insert_one(
            doc! {"_id":&peer,"workspace_id":owner,"owner_id":owner,"machine_id":machine,
            "credential_hash":&hash,"enabled":true,"ip":"10.203.0.8"},
        )
        .await?;
    app.collection(COLLECTION).insert_one(doc!{"_id":id,"workspace_id":owner,"state":"active","name":"Notebook","public_key":key,
        "public":false,"machine_ids":[machine],"mappings":[{"direction":"host","gatewayPort":27301}]}).await?;
    assert!(app
        .private_relay
        .workspace_generation(&owner.to_hex(), 0, false));
    let admission = app
        .private_relay
        .begin_workspace_admission(&peer, &hash, instance, &owner.to_hex())
        .unwrap();
    assert!(!app
        .private_relay
        .publish_admitted(
            &peer,
            &hash,
            instance,
            "10.203.0.8".parse()?,
            Default::default(),
            Some(admission)
        )
        .is_empty());

    let unix = dir.path().join("broker.sock");
    let (_stop, stopping) = watch::channel(false);
    let _broker = AbortOnDropHandle::new(tokio::spawn({
        let app = app.clone();
        let path = unix.clone();
        async move { crate::port_forward_auth::listen(app, &path, stopping).await }
    }));
    while !unix.exists() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let ingress = TcpListener::bind("127.0.0.1:0").await?;
    let ssh_port = ingress.local_addr()?.port();
    let _transport = AbortOnDropHandle::new(tokio::spawn(async move {
        let (mut tcp, _) = ingress.accept().await?;
        let mut unix = UnixStream::connect(unix).await?;
        tokio::io::copy_bidirectional(&mut tcp, &mut unix).await
    }));
    let known_hosts = dir.path().join("known_hosts");
    std::fs::write(&known_hosts, format!("[127.0.0.1]:{ssh_port} {host_key}\n"))?;
    let mut ssh = Command::new("ssh")
        .kill_on_drop(true)
        .env_remove("SSH_AUTH_SOCK")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .args([
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "PermitRemoteOpen=127.0.0.1:*",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            &format!("UserKnownHostsFile={}", known_hosts.display()),
            "-i",
        ])
        .arg(&identity)
        .args([
            "-p",
            &ssh_port.to_string(),
            "-N",
            "-R",
            "127.0.0.1:27301",
            &format!("pf-{id}@127.0.0.1"),
        ])
        .spawn()?;
    while !app
        .forward_registry
        .get(&id.to_hex())
        .is_some_and(|g| g.is_listening(27301))
    {
        ensure!(ssh.try_wait()?.is_none(), "SSH client exited");
        tokio::time::sleep(Duration::from_millis(15)).await;
    }

    let api = TcpListener::bind("127.0.0.1:0").await?;
    let api_addr = api.local_addr()?;
    let routes = router().with_state(app.clone());
    let _api = AbortOnDropHandle::new(tokio::spawn(async move { axum::serve(api, routes).await }));
    let mut headers = HeaderMap::new();
    headers.insert("x-porthub-peer", peer.parse()?);
    headers.insert("authorization", format!("Bearer {token}").parse()?);
    headers.insert("x-porthub-instance", instance.parse()?);
    headers.insert("x-porthub-host-forwards", "1".parse()?);
    let catalog = config(State(app.clone()), headers.clone())
        .await
        .map_err(api_error)?
        .into_response();
    let catalog: Value = serde_json::from_slice(&to_bytes(catalog.into_body(), 65536).await?)?;
    assert_eq!(catalog["hosts"][0]["host"], "notebook.forwards.phub");

    let service = TcpListener::bind("127.0.0.1:0").await?;
    let request = || -> Result<_> {
        let mut req = format!(
            "ws://{api_addr}/api/port-forwards/agent/{id}/{}/host-connect",
            service.local_addr()?.port()
        )
        .into_client_request()?;
        req.headers_mut().extend(headers.clone());
        Ok(req)
    };
    let (mut socket, _) = connect_async(request()?).await?;
    socket
        .send(Frame::binary(
            "GET /lab HTTP/1.1\r\nHost: notebook.forwards.phub\r\n\r\n",
        ))
        .await?;
    let (mut http, _) = service.accept().await?;
    let mut received = [0u8; 55];
    let expected = b"GET /lab HTTP/1.1\r\nHost: notebook.forwards.phub\r\n\r\n";
    http.read_exact(&mut received[..expected.len()]).await?;
    assert_eq!(&received[..expected.len()], expected);
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
    http.write_all(response).await?;
    let mut bytes = Vec::new();
    while bytes.len() < response.len() {
        let Frame::Binary(chunk) = socket.next().await.context("expected HTTP response")?? else {
            anyhow::bail!("unexpected WebSocket frame")
        };
        bytes.extend_from_slice(&chunk);
    }
    assert_eq!(bytes, response);
    app.collection(COLLECTION)
        .update_one(doc! {"_id":id}, doc! {"$set":{"machine_ids":[]}})
        .await?;
    signal(&app, owner);
    assert!(!matches!(socket.next().await, Some(Ok(Frame::Binary(_)))));
    assert!(
        matches!(connect_async(request()?).await, Err(tokio_tungstenite::tungstenite::Error::Http(r)) if r.status()==StatusCode::FORBIDDEN)
    );
    // Independently publish one service. Private audience remains revoked.
    let external = TcpListener::bind("127.0.0.1:0").await?;
    let external_port = external.local_addr()?.port();
    drop(external);
    let record = doc! {"_id":ObjectId::new(), "forward_owner":owner, "forward_reservation":id,
    "external_port":i32::from(external_port),"host_client_port":i32::from(service.local_addr()?.port()),
    "enabled":false,"host_public_state":"active"};
    app.collection("connections").insert_one(&record).await?;
    super::super::host_public::activate(&app, &record).await?;
    let mut visitor = tokio::net::TcpStream::connect(("127.0.0.1", external_port)).await?;
    visitor.write_all(expected).await?;
    let (mut exported, _) = service.accept().await?;
    exported.read_exact(&mut received[..expected.len()]).await?;
    assert_eq!(&received[..expected.len()], expected);
    exported.write_all(response).await?;
    let mut reply = vec![0; response.len()];
    visitor.read_exact(&mut reply).await?;
    assert_eq!(reply, response);
    assert!(
        matches!(connect_async(request()?).await, Err(tokio_tungstenite::tungstenite::Error::Http(r)) if r.status()==StatusCode::FORBIDDEN)
    );
    super::super::host_public::withdraw(&app, &record).await?;
    assert!(tokio::net::TcpStream::connect(("127.0.0.1", external_port))
        .await
        .is_err());
    ssh.kill().await?;
    Ok(())
}

fn api_error(e: ApiError) -> anyhow::Error {
    anyhow!("{}: {}", e.status, e.detail)
}
