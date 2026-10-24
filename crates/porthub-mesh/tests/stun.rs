use anyhow::Result;
use porthub_mesh::{Identity, Peer, State};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};
use stun::{
    agent::TransactionId,
    message::{Message, BINDING_SUCCESS},
    xoraddr::XorMappedAddress,
};
use tokio::net::UdpSocket;

#[tokio::test]
async fn reflexive_gathering_checks_source_and_random_transaction_on_the_bound_socket() -> Result<()>
{
    let server = UdpSocket::bind("127.0.0.1:0").await?;
    let address = server.local_addr()?;
    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let local = client.local_addr()?;
    let mapped: SocketAddr = "203.0.113.7:42345".parse()?;
    let fixture = tokio::spawn(async move {
        let mut bytes = [0u8; 2048];
        let (size, source) = server.recv_from(&mut bytes).await?;
        anyhow::ensure!(source == local);
        let mut request = Message::new();
        request.unmarshal_binary(&bytes[..size])?;
        anyhow::ensure!(request.transaction_id != TransactionId::default());
        let mut wrong = Message::new();
        wrong.build(&[
            Box::new(TransactionId::new()),
            Box::new(BINDING_SUCCESS),
            Box::new(XorMappedAddress {
                ip: mapped.ip(),
                port: 9,
            }),
        ])?;
        server.send_to(&wrong.raw, source).await?;
        let mut correct = Message::new();
        correct.build(&[
            Box::new(request.transaction_id),
            Box::new(BINDING_SUCCESS),
            Box::new(XorMappedAddress {
                ip: mapped.ip(),
                port: mapped.port(),
            }),
        ])?;
        let rogue = UdpSocket::bind("127.0.0.1:0").await?;
        let mut forged_source = Message::new();
        forged_source.build(&[
            Box::new(request.transaction_id),
            Box::new(BINDING_SUCCESS),
            Box::new(XorMappedAddress {
                ip: mapped.ip(),
                port: 10,
            }),
        ])?;
        rogue.send_to(&forged_source.raw, source).await?;
        server.send_to(&correct.raw, source).await?;
        anyhow::Ok(())
    });
    assert_eq!(
        porthub_mesh::stun::mapped(&client, &[format!("stun:{address}")]).await,
        Some(mapped)
    );
    fixture.await??;
    Ok(())
}

#[test]
fn reflexive_only_peers_keep_enrolled_identity_and_send_from_the_original_interface() -> Result<()>
{
    let a = Identity::new()?;
    let b = Identity::new()?;
    let base_a: SocketAddr = "10.1.0.2:40001".parse()?;
    let base_b: SocketAddr = "10.2.0.2:40002".parse()?;
    let public_a: SocketAddr = "198.51.100.1:50001".parse()?;
    let public_b: SocketAddr = "203.0.113.2:50002".parse()?;
    let start = Instant::now();
    let mut left = Peer::new(
        start,
        base_a,
        "peer-a",
        "peer-b",
        a.clone(),
        b.fingerprint(),
    )?;
    let mut right = Peer::new(start, base_b, "peer-b", "peer-a", b, a.fingerprint())?;
    left.add_reflexive(base_a, public_a)?;
    right.add_reflexive(base_b, public_b)?;
    let reflexive = |peer: &Peer| {
        let mut description = peer.description();
        description.sdp = description
            .sdp
            .lines()
            .filter(|line| !line.starts_with("a=candidate:") || line.contains(" typ srflx "))
            .collect::<Vec<_>>()
            .join("\r\n")
            + "\r\n";
        description
    };
    left.remote(start, "peer-b", &reflexive(&right))?;
    right.remote(start, "peer-a", &reflexive(&left))?;
    // Simulate only the address translation performed by two NATs. The ICE
    // and certificate-pinned DTLS protocols remain the actual implementations.
    let mut ready = None;
    for tick in 0..200 {
        let now = start + Duration::from_millis(tick * 50);
        if left.next_timeout().is_some_and(|deadline| deadline <= now) {
            left.timeout(now)?;
        }
        if right.next_timeout().is_some_and(|deadline| deadline <= now) {
            right.timeout(now)?;
        }
        for _ in 0..30 {
            let mut count = 0;
            while let Some(packet) = left.transmit() {
                assert_eq!(packet.local, base_a);
                assert_eq!(packet.remote, public_b);
                right.receive_on(now, base_b, public_a, packet.bytes)?;
                count += 1;
            }
            while let Some(packet) = right.transmit() {
                assert_eq!(packet.local, base_b);
                assert_eq!(packet.remote, public_a);
                left.receive_on(now, base_a, public_b, packet.bytes)?;
                count += 1;
            }
            if count == 0 {
                break;
            }
        }
        if left.state() == State::Ready && right.state() == State::Ready {
            ready = Some(now);
            break;
        }
    }
    let now = ready.ok_or_else(|| anyhow::anyhow!("reflexive peer negotiation did not finish"))?;
    left.send(now, &[0x45; 1380])?;
    let packet = left.transmit().expect("DTLS packet");
    assert_eq!(packet.local, base_a);
    assert_eq!(packet.remote, public_b);
    right.receive_on(now, base_b, public_a, packet.bytes)?;
    assert_eq!(right.packet().as_deref(), Some(&[0x45; 1380][..]));
    Ok(())
}
