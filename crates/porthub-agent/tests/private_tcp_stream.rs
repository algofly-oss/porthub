#![cfg(feature = "private-stream")]
use anyhow::{ensure, Context, Result};
use porthub_agent::private_network::tcp_stream::{self, Flow};
use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn tcp_stream_adapter_preserves_large_payloads_and_bidirectional_half_close() -> Result<()> {
    let (client, mut client_packets, client_runner) = tcp_stream::stack()?;
    let (server, mut server_packets, server_runner) = tcp_stream::stack()?;
    let cancel = CancellationToken::new();
    let mut tasks = JoinSet::new();
    tasks.spawn(client_runner.run(cancel.clone()));
    tasks.spawn(server_runner.run(cancel.clone()));
    let (accepted, mut accepting) = mpsc::channel(8);
    let wire_cancel = cancel.clone();
    let wire_client = client.clone();
    tasks.spawn(async move {
        let mut opening = HashSet::new();
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                _ = wire_cancel.cancelled() => return Ok(()),
                packet = client_packets.recv() => {
                    let Some(packet) = packet else { ensure!(wire_cancel.is_cancelled(), "client packet channel stopped"); return Ok(()); };
                    let flow = Flow::from_packet(&packet).context("invalid client TCP packet")?;
                    if opening.insert(flow) {
                        let server = server.clone();
                        let accepted = accepted.clone();
                        connections.spawn(async move { let result = server.accept_syn(packet).await; let _ = accepted.send(result).await; });
                    } else { server.packet(packet)?; }
                },
                packet = server_packets.recv() => {
                    let Some(packet) = packet else { ensure!(wire_cancel.is_cancelled(), "server packet channel stopped"); return Ok(()); };
                    wire_client.packet(packet)?;
                },
                _ = connections.join_next(), if !connections.is_empty() => {},
            }
        }
    });
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let flow = Flow {
            source: SocketAddrV4::new(Ipv4Addr::new(10, 234, 250, 1), 35001),
            destination: SocketAddrV4::new(Ipv4Addr::new(10, 234, 250, 2), 41231),
        };
        let mut source = client.connect(flow).await?;
        let (received_flow, mut destination) = accepting
            .recv()
            .await
            .context("connection not accepted")??;
        ensure!(received_flow == flow);
        let payload: Vec<_> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
        let sending = async {
            source.write_all(&payload).await?;
            source.shutdown().await?;
            let mut reply = Vec::new();
            source.read_to_end(&mut reply).await?;
            ensure!(reply == b"received");
            Ok::<_, anyhow::Error>(())
        };
        let receiving = async {
            let mut data = Vec::new();
            destination.read_to_end(&mut data).await?;
            ensure!(data == payload);
            destination.write_all(b"received").await?;
            destination.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        };
        tokio::try_join!(sending, receiving)?;
        Ok::<_, anyhow::Error>(())
    })
    .await;
    cancel.cancel();
    while let Some(task) = tasks.join_next().await {
        task??;
    }
    result.context("TCP stream adapter transfer timed out")?
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires an owned disposable container network namespace, /dev/net/tun and NET_ADMIN"]
async fn kernel_tcp_interoperates_in_both_directions_and_preserves_private_source_identity(
) -> Result<()> {
    use porthub_agent::private_network::device::Tun;
    use std::{net::SocketAddr, sync::Arc};
    use tokio::net::{TcpListener, TcpStream};
    ensure!(
        std::env::var("PORTHUB_TEST_OWNED_NETNS").as_deref() == Ok("1")
            && std::path::Path::new("/.dockerenv").is_file(),
        "requires an owned disposable container namespace"
    );
    let local = Ipv4Addr::new(10, 244, 254, 1);
    let remote = Ipv4Addr::new(10, 244, 254, 2);
    let tun = Arc::new(Tun::open("ph0123abcd", local, &[remote]).await?);
    let (adapter, mut packets, runner) = tcp_stream::stack()?;
    let cancel = CancellationToken::new();
    let mut tasks = JoinSet::new();
    tasks.spawn(runner.run(cancel.clone()));
    let output_tun = tun.clone();
    let output_cancel = cancel.clone();
    tasks.spawn(async move { loop { tokio::select! {
        _=output_cancel.cancelled()=>return Ok(()),
        packet=packets.recv()=>{
            let Some(packet)=packet else {ensure!(output_cancel.is_cancelled(),"adapter packet channel stopped");return Ok(());};
            output_tun.write(&packet).await?;
        },
    } } });
    let input_tun = tun.clone();
    let input_cancel = cancel.clone();
    let input_adapter = adapter.clone();
    let (accepted, mut accepting) = mpsc::channel(4);
    tasks.spawn(async move {
        let mut bytes = [0; 1600]; let mut incoming = HashSet::new(); let mut connections = JoinSet::new();
        loop { tokio::select! {
            _=input_cancel.cancelled()=>return Ok(()),
            packet=input_tun.read(&mut bytes)=>{
                let size=packet?; let packet=bytes::Bytes::copy_from_slice(&bytes[..size]);
                let Some(flow)=Flow::from_packet(&packet) else { continue; };
                if flow.destination==SocketAddrV4::new(remote,49072) {
                    if let Ok(reset)=tcp_stream::reject_syn(&packet) {input_tun.write(&reset).await?;}
                    continue;
                }
                if flow.destination==SocketAddrV4::new(remote,49071) && incoming.insert(flow) {
                    let adapter=input_adapter.clone();let accepted=accepted.clone();
                    connections.spawn(async move { let result=adapter.accept_syn(packet).await;let _=accepted.send(result).await; });
                } else { input_adapter.packet(packet)?; }
            },
            _=connections.join_next(),if !connections.is_empty()=>{},
        } }
    });
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let mut application = TcpStream::connect((remote, 49071)).await?;
        let (_, mut stream) = accepting
            .recv()
            .await
            .context("kernel connection not accepted")??;
        application.write_all(b"source").await?;
        let mut payload = [0; 6];
        stream.read_exact(&mut payload).await?;
        ensure!(&payload == b"source");
        stream.write_all(b"answer").await?;
        application.read_exact(&mut payload).await?;
        ensure!(&payload == b"answer");
        application.shutdown().await?;
        let mut eof = [0; 1];
        ensure!(stream.read(&mut eof).await? == 0);
        let refused =
            tokio::time::timeout(Duration::from_secs(1), TcpStream::connect((remote, 49072)))
                .await?;
        ensure!(
            refused.is_err_and(|error| error.kind() == std::io::ErrorKind::ConnectionRefused),
            "private TCP reset was not delivered to the kernel"
        );

        let listener = TcpListener::bind((local, 0)).await?;
        let flow = Flow {
            source: SocketAddrV4::new(remote, 35002),
            destination: SocketAddrV4::new(local, listener.local_addr()?.port()),
        };
        let connecting = adapter.connect(flow);
        let accepting = listener.accept();
        let (mut stream, (mut service, peer)) = tokio::try_join!(connecting, async {
            Ok::<_, anyhow::Error>(accepting.await?)
        })?;
        ensure!(
            peer == SocketAddr::V4(flow.source),
            "private source identity changed"
        );
        stream.write_all(b"target").await?;
        service.read_exact(&mut payload).await?;
        ensure!(&payload == b"target");
        service.write_all(b"reply!").await?;
        stream.read_exact(&mut payload).await?;
        ensure!(&payload == b"reply!");
        if let Some(mib) = std::env::var("PORTHUB_TEST_PAYLOAD_MIB")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|mib| *mib > 0 && *mib <= 128)
        {
            let data = vec![0u8; mib * 1024 * 1024];
            let started = std::time::Instant::now();
            let sending = stream.write_all(&data);
            let receiving = async {
                let mut reader = (&mut service).take(data.len() as u64);
                tokio::io::copy(&mut reader, &mut tokio::io::sink()).await
            };
            let (_, count) = tokio::try_join!(sending, receiving)?;
            ensure!(count == data.len() as u64);
            eprintln!(
                "Kernel TCP stream diagnostic: {:.2} MB/s",
                count as f64 / started.elapsed().as_secs_f64() / 1_000_000.0
            );
        }
        adapter.close(flow).await?;
        match service.read(&mut eof).await {
            Ok(0) | Err(_) => {}
            _ => anyhow::bail!("revoked TCP flow stayed open"),
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;
    cancel.cancel();
    while let Some(task) = tasks.join_next().await {
        task??;
    }
    drop(tun);
    result.context("kernel TCP adapter test timed out")?
}
