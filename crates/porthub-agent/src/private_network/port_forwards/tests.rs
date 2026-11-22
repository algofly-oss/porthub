use super::*;
use crate::private_network::authority_clock::{NativeClock, RequestWindow};
use axum::{
    extract::{
        ws::{Message, WebSocketUpgrade},
        Path, State,
    },
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde_json::{json, Value};
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
const ID: &str = "0123456789abcdef01234567";
const HOST: &str = "0123456789abcdef01234567.forwards.fixture.test";
const PEER: &str = "000000000000000000000001:000000000000000000000002";
const TOKEN: &str = "test-private-credential-scope-12345678";

#[derive(Default)]
struct Fixture {
    rows: RwLock<Vec<Value>>,
    catalogs: AtomicUsize,
    streams: AtomicUsize,
}
fn authorized(headers: &HeaderMap) -> bool {
    headers.get("authorization").and_then(|s| s.to_str().ok())
        == Some(format!("Bearer {TOKEN}").as_str())
        && headers.get("x-porthub-peer").and_then(|s| s.to_str().ok()) == Some(PEER)
        && headers
            .get("x-porthub-instance")
            .and_then(|s| s.to_str().ok())
            == Some("test-instance")
}
async fn config(State(s): State<Arc<Fixture>>, headers: HeaderMap) -> axum::response::Response {
    if !authorized(&headers) || headers.get("x-porthub-host-forwards").is_none() {
        return StatusCode::FORBIDDEN.into_response();
    }
    s.catalogs.fetch_add(1, Ordering::SeqCst);
    Json(json!({"hosts":s.rows.read().unwrap().clone()})).into_response()
}
async fn socket(
    State(s): State<Arc<Fixture>>,
    Path((id, port)): Path<(String, u16)>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> axum::response::Response {
    let allowed = s
        .rows
        .read()
        .unwrap()
        .iter()
        .any(|row| row["entryId"] == id && row["address"].is_string() && port != 0);
    if !authorized(&headers) || !allowed {
        return StatusCode::FORBIDDEN.into_response();
    }
    s.streams.fetch_add(1, Ordering::SeqCst);
    ws.on_upgrade(move |mut ws| async move {
        let mut origin = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        while let Some(Ok(message)) = ws.recv().await {
            if let Message::Binary(bytes) = message {
                origin.write_all(&bytes).await.unwrap();
                if bytes.ends_with(b"\r\n\r\n") {
                    let mut response = Vec::new();
                    origin.read_to_end(&mut response).await.unwrap();
                    ws.send(Message::Binary(response.into())).await.unwrap();
                    ws.send(Message::Text("eof".into())).await.unwrap();
                    break;
                }
            }
        }
    })
}
fn authority(cursor: Option<Uuid>, control: &Arc<Control>) -> Result<Authority<()>> {
    let mut window = RequestWindow::start(Arc::new(NativeClock))?;
    window.workspace_generation = Some(Uuid::new_v4());
    let mut a = Authority::new(
        (),
        Some(window),
        chrono::Utc::now() + chrono::Duration::seconds(14),
    );
    a.forward_sync = cursor.map(|id| (id, control.clone()));
    Ok(a)
}
async fn wait_for(mut condition: impl FnMut() -> bool) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(4), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await
        }
    })
    .await?;
    Ok(())
}

#[test]
fn scoped_descriptors_reject_substituted_alias_and_duplicate_ports() {
    let parse = |rows: Value| {
        serde_json::from_value::<Catalog>(json!({"hosts":rows}))
            .unwrap()
            .validate("fixture.test")
    };
    let row = json!({"entryId":ID,"host":"notebook.forwards.fixture.test","address":"10.203.0.55","ports":[]});
    assert!(parse(json!([row])).is_ok());
    assert!(parse(json!([row, row])).is_err());
    for (key, value) in [
        ("host", json!("local.phub")),
        ("entryId", json!("../other")),
        ("host", json!("bad-.forwards.fixture.test")),
        ("address", json!("127.0.0.1")),
        ("ports", json!([0])),
        ("ports", json!([22, 22])),
    ] {
        let mut bad = row.clone();
        bad[key] = value;
        assert!(parse(json!([bad])).is_err());
    }
    assert!(serde_json::from_value::<Catalog>(json!({"forwards":[row]}))
        .unwrap()
        .hosts
        .is_empty());
}
#[tokio::test]
async fn private_dns_tcp_and_http_follow_the_requested_ssh_client_port() -> Result<()> {
    exercise_http(false).await
}
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires a dedicated network namespace with CAP_NET_ADMIN and /dev/net/tun"]
async fn kernel_tun_and_udp_dns_reach_ssh_client_services() -> Result<()> {
    exercise_http(true).await
}
async fn exercise_http(use_tun: bool) -> Result<()> {
    use super::super::{controller::Event, dns::Zone};
    use hickory_proto::{
        op::{Message as Dns, Query},
        rr::{rdata::A, Name, RData, RecordType},
    };
    use porthub_network::tcp_stream::{self, Flow};
    let source: Ipv4Addr = "10.203.0.2".parse()?;
    let target: Ipv4Addr = "10.203.0.55".parse()?;
    let fixture = Arc::new(Fixture::default());
    let canonical = "notebook.forwards.fixture.test";
    *fixture.rows.write().unwrap() =
        vec![json!({"entryId":ID,"host":canonical,"address":target,"ports":[]})];
    let gateway = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let server = format!("http://{}", gateway.local_addr()?);
    let app = Router::new()
        .route("/api/port-forwards/agent/config", get(config))
        .route(
            "/api/port-forwards/agent/{id}/{port}/host-connect",
            get(socket),
        )
        .with_state(fixture.clone());
    let gw = tokio::spawn(async move { axum::serve(gateway, app).await });
    let profile = Profile {
        server,
        peer_id: PEER.into(),
        workspace: "000000000000000000000001".into(),
        token: TOKEN.into(),
        account_email: None,
        fallback_servers: vec![],
        allow_insecure_http_for_tests: true,
    };
    let control = Arc::new(Control::new_private(&profile)?);
    let manager = Manager::new(profile, "test-instance".into());
    manager.capture(Some(source), &["10.203.0.0/24".parse()?]);
    manager.update(
        &authority(Some(Uuid::new_v4()), &control)?,
        Some("fixture.test"),
    );
    let names = manager.names();
    wait_for(|| names.address(HOST) == Some(target)).await?;
    let mut zone = Zone::default();
    zone.update(&serde_json::from_value(json!({"workspace":"w","self":"a","revision":1,"expires_at":chrono::Utc::now()+chrono::Duration::seconds(30),"peers":[{"id":"a","ip":source,"hostname":"a.fixture.test","fingerprint":"local","instance":"local-instance"}],"grants":[]}))?)?;
    zone.forward_names = Some(names.clone());
    let lookup = |name: &str| -> Result<Dns> {
        let mut query = Dns::query();
        query.add_query(Query::query(Name::from_ascii(name)?, RecordType::A));
        Ok(Dns::from_vec(&zone.answer(&query.to_vec()?).unwrap())?)
    };
    manager.capture(None, &[]);
    assert_eq!(
        lookup(canonical)?.metadata.response_code,
        hickory_proto::op::ResponseCode::ServFail
    );
    manager.capture(Some(source), &["10.203.0.0/24".parse()?]);
    for name in [canonical, HOST] {
        assert_eq!(lookup(name)?.answers[0].data, RData::A(A(target)));
    }
    let stop = CancellationToken::new();
    let (kernel, mut packets, runner) = tcp_stream::stack()?;
    tokio::spawn(runner.run(stop.clone()));
    let (tx, mut rx) = tokio::sync::mpsc::channel(128);
    let mut native = Native::new(names.clone(), tx, stop.clone())?;
    let k = kernel.clone();
    #[cfg(target_os = "linux")]
    let tun = if use_tun {
        let tun = super::super::device::Tun::open("tun0phdeadc0de", source, &[target]).await?;
        let dns = super::super::dns::Server::bind(source).await?;
        *dns.zone.write().await = zone.clone();
        let port = dns.port()?;
        tokio::spawn(dns.serve(stop.clone()));
        let socket = tokio::net::UdpSocket::bind((source, 0)).await?;
        let mut query = Dns::query();
        query.add_query(Query::query(Name::from_ascii(canonical)?, RecordType::A));
        socket.send_to(&query.to_vec()?, (source, port)).await?;
        let mut answer = [0; 512];
        let len = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut answer)).await??;
        assert_eq!(
            Dns::from_vec(&answer[..len])?.answers[0].data,
            RData::A(A(target))
        );
        Some(tun)
    } else {
        None
    };
    let bridge = tokio::spawn(async move {
        #[cfg(target_os = "linux")]
        if let Some(tun) = tun {
            let mut buffer = [0u8; 65536];
            loop {
                tokio::select! {
                    result=tun.read(&mut buffer)=>{let len=result?;native.packet(Some(source),target,&buffer[..len]);},
                    Some(Event::ForwardLocal(reply))=rx.recv()=>{native.deliver(reply,&tun,source).await?;}
                }
            }
        }
        loop {
            tokio::select! {
               Some(bytes)=packets.recv()=>{assert!(native.packet(Some(source),target,&bytes));},
               Some(Event::ForwardLocal(reply))=rx.recv()=>{native.deliver_with(reply,source,|bytes|async{k.packet(bytes)}).await?;}
            }
        }
        #[allow(unreachable_code)]
        anyhow::Ok(())
    });
    let cursor = Uuid::new_v4();
    for ephemeral in [40101, 40102] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut request = [0; 256];
            let n = s.read(&mut request).await.unwrap();
            assert!(request[..n].starts_with(b"GET /lab"));
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nlab")
                .await
                .unwrap();
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut s: porthub_egress::BoxStream = if use_tun {
                Box::new(TcpStream::connect((target, port)).await?)
            } else {
                Box::new(
                    kernel
                        .connect(Flow {
                            source: std::net::SocketAddrV4::new(source, ephemeral),
                            destination: std::net::SocketAddrV4::new(target, port),
                        })
                        .await?,
                )
            };
            manager.update(&authority(Some(cursor), &control)?, Some("fixture.test"));
            s.write_all(b"GET /lab HTTP/1.0\r\nHost: notebook.forwards.fixture.test\r\n\r\n")
                .await?;
            let mut response = vec![0; 41];
            s.read_exact(&mut response).await?;
            ensure!(response.ends_with(b"lab"), "wrong HTTP response");
            anyhow::Ok(())
        })
        .await??;
    }
    assert_eq!(fixture.streams.load(Ordering::SeqCst), 2);
    fixture.rows.write().unwrap().clear();
    manager.update(
        &authority(Some(Uuid::new_v4()), &control)?,
        Some("fixture.test"),
    );
    wait_for(|| names.address(HOST).is_none()).await?;
    let absent = lookup(canonical)?;
    assert!(absent.answers.is_empty());
    assert_eq!(
        absent.metadata.response_code,
        hickory_proto::op::ResponseCode::NXDomain
    );
    stop.cancel();
    bridge.abort();
    gw.abort();
    Ok(())
}
