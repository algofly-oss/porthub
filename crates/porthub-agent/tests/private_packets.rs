use chrono::{Duration, Utc};
use porthub_agent::private_network::{
    dns::Zone,
    policy::{Engine, Snapshot},
};
use serde_json::json;
fn snapshot() -> Snapshot {
    serde_json::from_value(json!({"workspace":"ws","self":"a","revision":1,
        "expires_at":Utc::now()+Duration::seconds(15),
        "peers":[{"id":"a","ip":"10.203.0.1","fingerprint":"","instance":"","hostname":"luna.phub"},
                 {"id":"b","ip":"10.203.0.2","fingerprint":"","instance":"","hostname":"miro.phub","aliases":["miro-extra.phub"]}],
        "grants":[{"source":"a","destination":"b","protocol":"tcp","ports":[{"start":8000,"end":8000}]}]})).unwrap()
}
fn packet(src: u8, dst: u8, sport: u16, dport: u16, flags: u8) -> Vec<u8> {
    let mut packet = vec![0; 40];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&40u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&[10, 203, 0, src]);
    packet[16..20].copy_from_slice(&[10, 203, 0, dst]);
    packet[20..22].copy_from_slice(&sport.to_be_bytes());
    packet[22..24].copy_from_slice(&dport.to_be_bytes());
    packet[32] = 0x50;
    packet[33] = flags;
    let mut sum = packet[..20]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u32::from(u16::from_be_bytes([p[0], p[1]])))
        .sum::<u32>();
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    packet
}
#[test]
fn private_acl_binds_identity_tracks_tcp_replies_and_revokes_open_flows() {
    let mut engine = Engine::default();
    engine.apply(snapshot()).unwrap();
    assert!(!engine.check(&packet(1, 2, 4000, 8001, 2), "b", false));
    assert!(!engine.check(&packet(1, 2, 4000, 8000, 16), "b", false));
    assert!(!engine.check(&packet(1, 2, 4000, 8000, 2), "impostor", false));
    assert!(!engine.check(&packet(1, 2, 4000, 8000, 2), "b", true));
    assert!(engine.check(&packet(1, 2, 4000, 8000, 2), "b", false));
    assert!(!engine.check(&packet(2, 1, 8000, 4000, 16), "b", true));
    assert!(engine.check(&packet(2, 1, 8000, 4000, 18), "b", true));
    assert!(engine.check(&packet(1, 2, 4000, 8000, 16), "b", false));
    assert!(engine.check(&packet(2, 1, 8000, 4000, 16), "b", true));
    let mut changed = snapshot();
    changed.revision = 2;
    changed.grants.clear();
    engine.apply(changed).unwrap();
    assert!(!engine.check(&packet(2, 1, 8000, 4000, 16), "b", true));
    assert!(!engine.check(&packet(1, 2, 4000, 8000, 16), "b", false));
}
#[test]
fn unrelated_peer_changes_preserve_established_transfers_but_endpoint_changes_revoke_them() {
    for change in ["fingerprint", "instance", "address", "removal"] {
        let mut policy = snapshot();
        let mut third = policy.peers[1].clone();
        third.id = "c".into();
        third.ip = "10.203.0.3".parse().unwrap();
        third.hostname = "third.phub".into();
        policy.peers.push(third);
        let mut engine = Engine::default();
        engine.apply(policy.clone()).unwrap();
        assert!(engine.check(&packet(1, 2, 4000, 8000, 2), "b", false));
        assert!(engine.check(&packet(2, 1, 8000, 4000, 18), "b", true));
        assert!(engine.check(&packet(1, 2, 4000, 8000, 16), "b", false));
        policy.revision += 1;
        match change {
            "fingerprint" => policy.peers[2].fingerprint = "replacement certificate".into(),
            "instance" => policy.peers[2].instance = "restarted process".into(),
            "address" => policy.peers[2].ip = "10.203.0.4".parse().unwrap(),
            "removal" => {
                policy.peers.pop();
            }
            _ => unreachable!(),
        }
        engine.apply(policy.clone()).unwrap();
        assert!(
            engine.check(&packet(2, 1, 8000, 4000, 16), "b", true),
            "unrelated {change}"
        );
        assert!(
            engine.check(&packet(1, 2, 4000, 8000, 16), "b", false),
            "unrelated {change}"
        );
        policy.revision += 1;
        policy.peers[1].fingerprint = "replacement endpoint certificate".into();
        engine.apply(policy).unwrap();
        assert!(!engine.check(&packet(2, 1, 8000, 4000, 16), "b", true));
        assert!(!engine.check(&packet(1, 2, 4000, 8000, 16), "b", false));
    }
}

#[test]
fn private_policy_rejects_overlapping_addresses_expired_lease_and_revision_rollback() {
    let mut engine = Engine::default();
    engine.apply(snapshot()).unwrap();
    let mut duplicate = snapshot();
    duplicate.peers[1].ip = duplicate.peers[0].ip;
    assert!(engine.apply(duplicate).is_err());
    assert!(!engine.check(&packet(1, 2, 4000, 8000, 2), "b", false));
    let mut expired = snapshot();
    expired.expires_at = Utc::now() - Duration::seconds(1);
    assert!(engine.apply(expired).is_err());
    let mut next = snapshot();
    next.revision = 3;
    engine.apply(next).unwrap();
    assert!(engine.apply(snapshot()).is_err());
    let mut corrupt = packet(1, 2, 4000, 8000, 2);
    corrupt[12] = 192;
    assert!(!engine.check(&corrupt, "b", false));
}
#[test]
fn private_dns_answers_only_assigned_zone_and_never_falls_through_for_known_ipv6() {
    use hickory_proto::{
        op::Query,
        op::{Message, ResponseCode},
        rr::{Name, RecordType},
    };
    let mut zone = Zone::default();
    zone.update(&snapshot()).unwrap();
    for (name, kind, code, count) in [
        ("miro.phub.", RecordType::A, ResponseCode::NoError, 1),
        ("miro-extra.phub.", RecordType::A, ResponseCode::NoError, 1),
        ("miro.phub.", RecordType::AAAA, ResponseCode::NoError, 0),
        ("unknown.phub.", RecordType::A, ResponseCode::NXDomain, 0),
        ("example.org.", RecordType::A, ResponseCode::Refused, 0),
    ] {
        let mut query = Message::query();
        query.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
        let answer = Message::from_vec(&zone.answer(&query.to_vec().unwrap()).unwrap()).unwrap();
        assert_eq!(answer.metadata.response_code, code);
        assert_eq!(answer.answers.len(), count);
    }
    assert!(zone.answer(&[0; 8]).is_none());
}

#[cfg(all(target_os = "linux", feature = "netns-tests"))]
#[tokio::test]
#[ignore = "requires explicitly owned disposable network namespace and NET_ADMIN"]
async fn owned_linux_tun_routes_kernel_udp_packets_and_cleans_up() -> anyhow::Result<()> {
    use nlink::netlink::{Connection, Route};
    use porthub_agent::private_network::device::Tun;
    use std::net::Ipv4Addr;
    use std::time::Duration;
    anyhow::ensure!(
        std::env::var("PORTHUB_TEST_OWNED_NETNS").as_deref() == Ok("1")
            && std::path::Path::new("/.dockerenv").is_file(),
        "test requires owned disposable container namespace"
    );
    let own = Ipv4Addr::new(10, 234, 251, 1);
    let remote = Ipv4Addr::new(10, 234, 251, 2);
    let tun = Tun::open("phab12cd34", own, &[remote]).await?;
    assert!(Tun::open("phab12cd34", own, &[remote]).await.is_err());
    let socket = tokio::net::UdpSocket::bind((own, 0)).await?;
    socket
        .send_to(b"native-kernel-packet", (remote, 9000))
        .await?;
    let mut packet = [0; 1380];
    let n = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let n = tun.read(&mut packet).await?;
            if n >= 20 && packet[0] >> 4 == 4 && packet[9] == 17 {
                break Ok::<_, anyhow::Error>(n);
            }
        }
    })
    .await??;
    assert_eq!(packet[9], 17);
    assert_eq!(&packet[12..16], &own.octets());
    assert_eq!(&packet[16..20], &remote.octets());
    let header = usize::from(packet[0] & 15) * 4;
    assert_eq!(&packet[header + 8..n], b"native-kernel-packet");
    for i in 0..4 {
        packet.swap(12 + i, 16 + i);
    }
    for i in 0..2 {
        packet.swap(header + i, header + 2 + i);
    }
    packet[header + 6..header + 8].fill(0);
    packet[10..12].fill(0);
    let mut sum = packet[..header]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u32::from(u16::from_be_bytes([p[0], p[1]])))
        .sum::<u32>();
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    tun.write(&packet[..n]).await?;
    let mut received = [0; 128];
    let (n, from) =
        tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut received)).await??;
    assert_eq!(&received[..n], b"native-kernel-packet");
    assert_eq!(from.ip(), std::net::IpAddr::V4(remote));
    tun.update_routes(&[Ipv4Addr::new(10, 234, 251, 3)]).await?;
    let netlink = Connection::<Route>::new()?;
    let index = tun.index;
    let routes = netlink.get_routes().await?;
    assert!(!routes.iter().any(|route| route.oif() == Some(index)
        && route.destination() == Some(&std::net::IpAddr::V4(remote))));
    drop(socket);
    drop(tun);
    assert!(netlink.get_link_by_name("phab12cd34").await?.is_none());
    Ok(())
}

#[test]
fn active_flows_keep_the_prechecked_route_and_fail_over_only_on_transport_failure() {
    use porthub_agent::private_network::{paths::Pinned, policy::Packet};
    let mut paths = Pinned::default();
    let a = Packet::parse(&packet(1, 2, 4000, 8000, 2)).unwrap();
    let reply = Packet::parse(&packet(2, 1, 8000, 4000, 18)).unwrap();
    assert_eq!(paths.choose(a, false, true), Some(false));
    assert_eq!(paths.choose(a, true, true), Some(false));
    assert_eq!(paths.choose(reply, true, true), Some(false));
    let new = Packet::parse(&packet(1, 2, 4001, 8000, 2)).unwrap();
    assert_eq!(paths.choose(new, true, true), Some(true));
    assert_eq!(paths.choose(new, false, true), Some(false));
    assert_eq!(paths.choose(new, true, true), Some(false));
    assert_eq!(paths.choose(new, true, false), None);
}

#[cfg(all(target_os = "linux", feature = "root-dns-test"))]
#[tokio::test]
#[ignore = "requires explicit host administrator access; owns only a temporary PortHub link"]
async fn linux_private_dns_resolves_through_the_owned_link_without_claiming_port_53(
) -> anyhow::Result<()> {
    use porthub_agent::private_network::{device::Tun, dns};
    use std::{net::Ipv4Addr, time::Duration};
    anyhow::ensure!(
        std::env::var("PORTHUB_TEST_HOST_DNS").as_deref() == Ok("1")
            && rustix::process::geteuid().is_root(),
        "explicit root DNS test required"
    );
    let tun = Tun::open("phc0d3fa01", Ipv4Addr::new(10, 234, 251, 1), &[]).await?;
    let server = dns::Server::bind(Ipv4Addr::new(10, 234, 251, 1)).await?;
    let port = server.port()?;
    let mut policy = snapshot();
    policy.peers.truncate(1);
    policy.peers[0].ip = Ipv4Addr::new(10, 234, 251, 1);
    policy.peers[0].hostname = "native.ph-native-test".into();
    policy.grants.clear();
    server.zone.write().await.update(&policy)?;
    let cancel = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(server.serve(cancel.clone()));
    dns::register(
        tun.index,
        Ipv4Addr::new(10, 234, 251, 1),
        port,
        "ph-native-test",
    )
    .await?;
    let connection = zbus::Connection::system().await?;
    let proxy = zbus::Proxy::new(
        &connection,
        "org.freedesktop.resolve1",
        "/org/freedesktop/resolve1",
        "org.freedesktop.resolve1.Manager",
    )
    .await?;
    let (addresses, _, _): (Vec<(i32, i32, Vec<u8>)>, String, u64) = tokio::time::timeout(
        Duration::from_secs(8),
        proxy.call(
            "ResolveHostname",
            &(
                tun.index as i32,
                "native.ph-native-test",
                libc::AF_INET,
                0u64,
            ),
        ),
    )
    .await??;
    assert!(addresses
        .iter()
        .any(|(_, family, ip)| *family == libc::AF_INET && ip == &[10, 234, 251, 1]));
    cancel.cancel();
    task.await??;
    drop(tun);
    Ok(())
}
