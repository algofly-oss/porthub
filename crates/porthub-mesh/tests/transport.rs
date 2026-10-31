use anyhow::Result;
use bytes::Bytes;
use porthub_mesh::{udp::Session, Description, Identity, Peer, State, MAX_PACKET};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

fn memory_pair() -> Result<(Peer, Peer, Instant)> {
    let now = Instant::now();
    let a = Identity::new()?;
    let b = Identity::new()?;
    let mut left = Peer::new(
        now,
        "127.0.0.1:41001".parse()?,
        "peer-a",
        "peer-b",
        a.clone(),
        b.fingerprint(),
    )?;
    let mut right = Peer::new(
        now,
        "127.0.0.1:41002".parse()?,
        "peer-b",
        "peer-a",
        b,
        a.fingerprint(),
    )?;
    left.remote(now, "peer-b", &right.description())?;
    right.remote(now, "peer-a", &left.description())?;
    Ok((left, right, now))
}
fn pump(left: &mut Peer, right: &mut Peer, now: Instant) -> Result<()> {
    for _ in 0..40 {
        let mut count = 0;
        while let Some(packet) = left.transmit() {
            right.receive(now, packet.local, packet.bytes)?;
            count += 1;
        }
        while let Some(packet) = right.transmit() {
            left.receive(now, packet.local, packet.bytes)?;
            count += 1;
        }
        if count == 0 {
            return Ok(());
        }
    }
    anyhow::bail!("protocol produced an unbounded synchronous packet loop")
}
fn connect(left: &mut Peer, right: &mut Peer, start: Instant) -> Result<Instant> {
    for i in 0..200 {
        let now = start + Duration::from_millis(i * 50);
        if left.next_timeout().is_some_and(|d| d <= now) {
            left.timeout(now)?;
        }
        if right.next_timeout().is_some_and(|d| d <= now) {
            right.timeout(now)?;
        }
        pump(left, right, now)?;
        if left.state() == State::Ready && right.state() == State::Ready {
            return Ok(now);
        }
    }
    anyhow::bail!("private handshake did not complete")
}
#[test]
fn ice_dtls_core_proves_both_certificates_and_preserves_packet_boundaries() -> Result<()> {
    let (mut left, mut right, start) = memory_pair()?;
    let now = connect(&mut left, &mut right, start)?;
    let packet = vec![0x45; MAX_PACKET];
    left.send(now, &packet)?;
    let encrypted = left.transmit().expect("encrypted packet");
    assert!(!encrypted.bytes.windows(packet.len()).any(|w| w == packet));
    right.receive(now, encrypted.local, encrypted.bytes.clone())?;
    assert_eq!(right.packet().as_deref(), Some(packet.as_slice()));
    // Record replay must not deliver the application packet twice.
    right.receive(now, encrypted.local, encrypted.bytes)?;
    assert!(right.packet().is_none());
    right.send(now, &packet[..20])?;
    pump(&mut left, &mut right, now)?;
    assert_eq!(left.packet().as_deref(), Some(&packet[..20]));
    assert!(left.send(now, &packet[..19]).is_err());
    assert!(left.send(now, &vec![0; MAX_PACKET + 1]).is_err());
    assert!(left.next_timeout().unwrap() >= now + Duration::from_secs(1));
    left.close(now);
    pump(&mut left, &mut right, now)?;
    assert_eq!(right.state(), State::Closed);
    Ok(())
}
#[test]
fn forged_description_cannot_substitute_a_different_certificate_even_on_the_same_address(
) -> Result<()> {
    let now = Instant::now();
    let real = Identity::new()?;
    let expected = Identity::new()?;
    let impostor = Identity::new()?;
    let mut left = Peer::new(
        now,
        "127.0.0.1:41001".parse()?,
        "peer-a",
        "peer-b",
        real.clone(),
        expected.fingerprint(),
    )?;
    let mut right = Peer::new(
        now,
        "127.0.0.1:41002".parse()?,
        "peer-b",
        "peer-a",
        impostor.clone(),
        real.fingerprint(),
    )?;
    let forged = Description {
        r#type: right.description().r#type,
        sdp: right
            .description()
            .sdp
            .replace(impostor.fingerprint(), expected.fingerprint()),
    };
    left.remote(now, "peer-b", &forged)?;
    right.remote(now, "peer-a", &left.description())?;
    assert!(connect(&mut left, &mut right, now).is_err());
    assert_ne!(left.state(), State::Ready);
    assert!(left.packet().is_none());
    Ok(())
}
#[test]
fn description_actor_fingerprint_and_size_fail_before_connectivity_changes() -> Result<()> {
    let now = Instant::now();
    let a = Identity::new()?;
    let b = Identity::new()?;
    let mut left = Peer::new(
        now,
        "127.0.0.1:41001".parse()?,
        "peer-a",
        "peer-b",
        a.clone(),
        b.fingerprint(),
    )?;
    let right = Peer::new(
        now,
        "127.0.0.1:41002".parse()?,
        "peer-b",
        "peer-a",
        b,
        a.fingerprint(),
    )?;
    assert!(left
        .remote(now, "another-peer", &right.description())
        .is_err());
    let mut bad = right.description();
    bad.sdp = bad
        .sdp
        .replace("a=porthub-peer-id:peer-b", "a=porthub-peer-id:another-peer");
    assert!(left.remote(now, "peer-b", &bad).is_err());
    assert_eq!(left.state(), State::Waiting);
    assert!(left.next_timeout().is_none());
    let mut bad = right.description();
    bad.sdp = "x".repeat(65537);
    assert!(left.remote(now, "peer-b", &bad).is_err());
    left.remote(now, "peer-b", &right.description())?;
    left.remote(now, "peer-b", &right.description())?;
    assert_eq!(left.state(), State::Connecting);
    assert!(!format!("{:?}", right.description()).contains("ice-pwd"));
    Ok(())
}

#[tokio::test]
async fn real_udp_peers_exchange_packets_and_release_their_owned_tasks() -> Result<()> {
    let a = Identity::new()?;
    let b = Identity::new()?;
    let bind: SocketAddr = "127.0.0.1:0".parse()?;
    let (left, mut received_left) =
        Session::bind(bind, "peer-a", "peer-b", a.clone(), b.fingerprint()).await?;
    let (right, mut received_right) =
        Session::bind(bind, "peer-b", "peer-a", b, a.fingerprint()).await?;
    left.remote("peer-b", right.description()).await?;
    right.remote("peer-a", left.description()).await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::try_join!(left.ready(), right.ready())
    })
    .await??;
    for i in 0..256u32 {
        let mut packet = vec![0x45; MAX_PACKET];
        packet[4..8].copy_from_slice(&i.to_be_bytes());
        let packet = Bytes::from(packet);
        left.send(packet.clone())?;
        let actual = tokio::time::timeout(Duration::from_secs(2), received_right.recv())
            .await?
            .expect("right packet");
        assert_eq!(actual, packet);
        right.send(actual)?;
        let actual = tokio::time::timeout(Duration::from_secs(2), received_left.recv())
            .await?
            .expect("left packet");
        assert_eq!(actual, packet);
    }
    assert_eq!(left.statistics().await?.sent_bytes, 256 * MAX_PACKET as u64);
    assert_eq!(
        right.statistics().await?.received_bytes,
        256 * MAX_PACKET as u64
    );
    left.close().await;
    assert_eq!(left.state(), State::Closed);
    tokio::time::timeout(Duration::from_secs(2), async {
        while right.state() != State::Closed {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    right.close().await;
    Ok(())
}

#[tokio::test]
async fn ipv6_direct_peers_survive_an_unavailable_interface_and_exchange_full_packets() -> Result<()>
{
    let a = Identity::new()?;
    let b = Identity::new()?;
    let interfaces = ["192.0.2.123:0".parse()?, "[::1]:0".parse()?];
    let (left, mut left_packets) =
        Session::bind_interfaces(&interfaces, "peer-a", "peer-b", a.clone(), b.fingerprint())
            .await?;
    let (right, mut right_packets) =
        Session::bind("[::1]:0".parse()?, "peer-b", "peer-a", b, a.fingerprint()).await?;
    assert!(left.description().sdp.contains("::1"));
    left.remote("peer-b", right.description()).await?;
    right.remote("peer-a", left.description()).await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::try_join!(left.ready(), right.ready())
    })
    .await??;
    assert!(!left.is_relay() && !right.is_relay());
    for n in 0..128u32 {
        let mut data = vec![0x45; MAX_PACKET];
        data[4..8].copy_from_slice(&n.to_be_bytes());
        let data = Bytes::from(data);
        left.send(data.clone())?;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), right_packets.recv()).await?,
            Some(data.clone())
        );
        right.send(data.clone())?;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), left_packets.recv()).await?,
            Some(data)
        );
    }
    left.close().await;
    right.close().await;
    assert_eq!(left.state(), State::Closed);
    assert_eq!(right.state(), State::Closed);
    assert!(Session::bind(
        "192.0.2.123:0".parse()?,
        "peer-a",
        "peer-b",
        a.clone(),
        a.fingerprint()
    )
    .await
    .is_err());
    Ok(())
}

#[test]
fn dual_stack_negotiation_uses_ipv6_when_every_ipv4_candidate_is_blackholed() -> Result<()> {
    let a = Identity::new()?;
    let b = Identity::new()?;
    let a6: SocketAddr = "[2001:db8:1::1]:41001".parse()?;
    let b6: SocketAddr = "[2001:db8:2::1]:41002".parse()?;
    let start = Instant::now();
    let mut left = Peer::new(
        start,
        "10.1.0.2:41001".parse()?,
        "peer-a",
        "peer-b",
        a.clone(),
        b.fingerprint(),
    )?;
    let mut right = Peer::new(
        start,
        "10.2.0.2:41002".parse()?,
        "peer-b",
        "peer-a",
        b,
        a.fingerprint(),
    )?;
    left.add_interface(a6)?;
    right.add_interface(b6)?;
    left.remote(start, "peer-b", &right.description())?;
    right.remote(start, "peer-a", &left.description())?;
    for tick in 0..200 {
        let now = start + Duration::from_millis(tick * 50);
        if left.next_timeout().is_some_and(|at| at <= now) {
            left.timeout(now)?;
        }
        if right.next_timeout().is_some_and(|at| at <= now) {
            right.timeout(now)?;
        }
        for _ in 0..30 {
            let mut count = 0;
            while let Some(packet) = left.transmit() {
                if packet.remote == b6 {
                    right.receive_on(now, b6, a6, packet.bytes)?;
                }
                count += 1;
            }
            while let Some(packet) = right.transmit() {
                if packet.remote == a6 {
                    left.receive_on(now, a6, b6, packet.bytes)?;
                }
                count += 1;
            }
            if count == 0 {
                break;
            }
        }
        if left.state() == State::Ready && right.state() == State::Ready {
            left.send(now, &[0x45; MAX_PACKET])?;
            let packet = left.transmit().expect("encrypted packet");
            assert_eq!((packet.local, packet.remote), (a6, b6));
            right.receive_on(now, b6, a6, packet.bytes)?;
            assert_eq!(right.packet().as_deref(), Some(&[0x45; MAX_PACKET][..]));
            assert!(!left.is_relay() && !right.is_relay());
            return Ok(());
        }
    }
    anyhow::bail!("IPv6 did not bypass the blackholed IPv4 candidates")
}

#[test]
fn dual_stack_descriptions_keep_ipv4_only_peers_compatible() -> Result<()> {
    let now = Instant::now();
    let a = Identity::new()?;
    let b = Identity::new()?;
    let mut left = Peer::new(
        now,
        "127.0.0.1:41001".parse()?,
        "peer-a",
        "peer-b",
        a.clone(),
        b.fingerprint(),
    )?;
    let mut right = Peer::new(
        now,
        "127.0.0.1:41002".parse()?,
        "peer-b",
        "peer-a",
        b,
        a.fingerprint(),
    )?;
    left.add_interface("[2001:db8::1]:41001".parse()?)?;
    left.remote(now, "peer-b", &right.description())?;
    right.remote(now, "peer-a", &left.description())?;
    let now = connect(&mut left, &mut right, now)?;
    left.send(now, &[0x45; MAX_PACKET])?;
    pump(&mut left, &mut right, now)?;
    assert_eq!(right.packet().as_deref(), Some(&[0x45; MAX_PACKET][..]));
    Ok(())
}
