use super::super::{Parent, Spec, authority_event, sparse};
use super::*;
use porthub_network::policy::{Lookup, PairLease, Snapshot};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};
use tokio_util::sync::CancellationToken;

fn admission() -> (
    Admission,
    watch::Sender<Option<authority_event::Authority<Vec<Spec>>>>,
) {
    let expiry = chrono::Utc::now() + chrono::Duration::seconds(15);
    let epoch = "a".repeat(64);
    let base:Snapshot=serde_json::from_value(serde_json::json!({"workspace":"w","self":"a","revision":1,"expires_at":expiry,"sparse":{"protocol":1,"epoch":epoch},"peers":[{"id":"a","ip":"10.203.0.2","fingerprint":"local","instance":"local-instance","hostname":"a.phub"}],"grants":[]})).unwrap();
    let lease:PairLease=serde_json::from_value(serde_json::json!({"workspace":"w","self":"a","epoch":epoch,"revision":1,"expires_at":expiry,"local":base.peers[0],"peer":{"id":"b","ip":"10.203.1.2","fingerprint":"remote","instance":"remote-instance","hostname":"b.phub"},"grants":[{"source":"b","destination":"a","protocol":"tcp","ports":[{"start":1,"end":65535}]},{"source":"b","destination":"a","protocol":"udp","ports":[{"start":1,"end":65535}]}]})).unwrap();
    let witness = authority_event::request_start(None).unwrap();
    let base_authority = authority_event::Authority::new((), witness.clone(), expiry);
    let (pairs, _) = sparse::channel();
    pairs.update_base_authority(&base, base_authority.clone());
    pairs.installed_authority(
        &Lookup {
            kind: "peer".into(),
            value: "b".into(),
        },
        lease,
        base_authority,
    );
    let spec = Spec {
        peer_id: "a".into(),
        target_ip: "192.168.1.8".parse().unwrap(),
        token: "t".repeat(48),
    };
    let (list, assignments) = watch::channel(Some(authority_event::Authority::new(
        vec![spec.clone()],
        witness,
        expiry,
    )));
    let parent = Parent {
        spec: Arc::new(spec),
        assignments,
        stop: CancellationToken::new(),
    };
    let domain = pairs
        .pair_authority("b")
        .unwrap()
        .retirement_domain()
        .unwrap();
    (
        Admission {
            pairs,
            parent,
            domain,
            peer: "b".into(),
        },
        list,
    )
}

fn flow(port: u16) -> Flow {
    Flow {
        source: "10.203.1.2:40999".parse().unwrap(),
        destination: SocketAddrV4::new("10.203.0.2".parse().unwrap(), port),
    }
}

#[tokio::test]
async fn udp_reaches_configured_socket_and_parent_withdrawal_invalidates_queued_reply() -> Result<()>
{
    let (grant, assignments) = admission();
    let server = UdpSocket::bind("127.0.0.1:0").await?;
    let flow = flow(server.local_addr()?.port());
    let (stack, _, _) = tagged::stack()?;
    let (output, mut rx) = mpsc::channel(4);
    let mut routes = Flows::new(stack, output);
    routes
        .receive(
            udp_frame(flow, b"question"),
            grant.clone(),
            grant.current().unwrap(),
            &Lan::loopback_fixture(),
        )
        .await;
    let mut bytes = [0; 16];
    let (n, from) =
        tokio::time::timeout(Duration::from_secs(2), server.recv_from(&mut bytes)).await??;
    assert_eq!(&bytes[..n], b"question");
    server.send_to(b"answer", from).await?;
    let (peer, reply, permit) = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await?
        .unwrap();
    assert_eq!(peer, "b");
    assert_eq!(
        udp_payload(&reply).unwrap(),
        (flow.reverse(), Bytes::from_static(b"answer"))
    );
    assert!(permit.valid());
    assignments.send_replace(None);
    assert!(!permit.valid());
    routes.prune();
    assert!(routes.udp.is_empty());
    Ok(())
}

#[tokio::test]
async fn tcp_carries_both_directions_and_retires_the_live_socket_on_acl_revocation() -> Result<()> {
    let (grant, _assignments) = admission();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let flow = flow(listener.local_addr()?.port());
    let stop = CancellationToken::new();
    let _guard = stop.clone().drop_guard();
    let (client, mut from_client, client_stack) = tagged::stack()?;
    let (server, mut from_server, server_stack) = tagged::stack()?;
    let (output, _rx) = mpsc::channel(4);
    let mut routes = Flows::new(server, output);
    let mut background = JoinSet::new();
    background.spawn(client_stack.run(stop.clone()));
    background.spawn(server_stack.run(stop.clone()));
    let permit = grant.current().unwrap();
    let pending = client.prepare_connect(flow, permit.clone()).await?;
    let client_input = pending.ingress();
    let path = grant.clone();
    background.spawn(async move{
        let lan=Lan::loopback_fixture();let mut tick=tokio::time::interval(Duration::from_millis(20));
        loop{tokio::select!{
            _=tick.tick()=>routes.prune(),
            Some(packet)=from_client.recv()=>{
                if let Some(active)=path.current(){
                    packet.deliver(|data|async {routes.receive(data,path.clone(),active,&lan).await;Ok(())}).await?;
                }
            }
            Some(packet)=from_server.recv()=>{
                if let Some((_,active))=routes.tcp_egress(&packet){
                    packet.deliver(|data|async {client_input.input(data,active)}).await?;
                }
            }
        }}
    });
    tokio::time::timeout(Duration::from_secs(8), async {
        let conn = pending.established().await?;
        let (mut socket, _) = listener.accept().await?;
        let id = [1; 16];
        let ack = conn
            .write_chunk(id, 0, Bytes::from_static(b"request"), permit.clone())
            .await?;
        conn.publish_receipt(ack, id, 0, 7, || async { Ok(()) })
            .await?;
        let mut bytes = [0; 7];
        socket.read_exact(&mut bytes).await?;
        assert_eq!(&bytes, b"request");
        socket.write_all(b"response").await?;
        conn.read_chunk()
            .await?
            .deliver(|data, eof| async move {
                assert_eq!(&data[..], b"response");
                assert!(!eof);
                Ok(())
            })
            .await?;
        grant.pairs.revoke_all();
        assert!(!permit.valid());
        assert_eq!(socket.read(&mut bytes).await?, 0);
        anyhow::Ok(())
    })
    .await??;
    Ok(())
}
