use chrono::{Duration, Utc};
use porthub_agent::private_network::{
    dns::Zone,
    policy::{Engine, Snapshot},
};
use serde_json::json;
fn snapshot() -> Snapshot {
    serde_json::from_value(json!({"workspace":"ws","self":"a","revision":1,
        "expires_at":Utc::now()+Duration::seconds(15),
        "dns_suffixes":["phub","phub.io"],
        "peers":[{"id":"a","ip":"10.203.0.1","fingerprint":"","instance":"","hostname":"luna.phub"},
                 {"id":"b","ip":"10.203.0.2","fingerprint":"","instance":"","hostname":"miro.phub","aliases":["miro-extra.phub","condor.phub.io"]}],
        "grants":[{"source":"a","destination":"b","protocol":"tcp","ports":[{"start":8000,"end":8000}]}]})).unwrap()
}
fn packet(src: u8, dst: u8, sport: u16, dport: u16, flags: u8) -> Vec<u8> {
    addressed_packet([10, 203, 0, src], [10, 203, 0, dst], sport, dport, flags)
}
fn addressed_packet(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8) -> Vec<u8> {
    let mut packet = vec![0; 40];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&40u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&src);
    packet[16..20].copy_from_slice(&dst);
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
fn closed_private_tcp_ports_can_return_a_reset_during_the_handshake() {
    let mut policy = Engine::default();
    policy.apply(snapshot()).unwrap();
    assert!(!policy.check(&packet(2, 1, 8000, 40000, 0x14), "b", true));
    assert!(policy.check(&packet(1, 2, 40000, 8000, 0x02), "b", false));
    assert!(policy.check(&packet(2, 1, 8000, 40000, 0x14), "b", true));
    assert!(!policy.check(&packet(1, 2, 40000, 8000, 0x10), "b", false));
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
fn exit_traffic_is_peer_bound_stateful_and_separate_from_private_acl() {
    let mut config = snapshot();
    let mut second_exit = config.peers[1].clone();
    second_exit.id = "c".into(); second_exit.ip = "10.203.0.3".parse().unwrap();
    config.peers.push(second_exit);
    for peer in &mut config.peers { peer.fingerprint = "test-fingerprint".into(); peer.instance = "test-instance".into(); }
    config.grants.clear();
    config.exit_routes = serde_json::from_value(json!([{"id":"internet","name":"Internet","routing_peers":["b","c"],"clients":["a"]}])).unwrap();
    let mut client = Engine::default(); client.apply(config.clone()).unwrap();
    let mut exit = Engine::default(); let mut exit_config = config.clone(); exit_config.self_ = "b".into(); exit.apply(exit_config).unwrap();
    let local = [10,203,0,1]; let public = [8,8,8,8];
    let syn = addressed_packet(local, public, 40000, 443, 2);
    let mut placeholder = config.clone(); placeholder.peers[1].fingerprint.clear();
    let mut pending = Engine::default(); pending.apply(placeholder).unwrap();
    assert!(!pending.check_exit(&syn, "b", false));
    let reply = addressed_packet(public, local, 443, 40000, 18);
    let ack = addressed_packet(local, public, 40000, 443, 16);
    assert!(!client.check_exit(&reply, "b", true));
    assert!(!client.check_exit(&syn, "unknown", false));
    assert!(!client.check_exit(&syn, "b", true));
    assert!(!client.check(&syn, "b", false));
    assert!(client.check_exit(&syn, "b", false));
    assert!(!client.check_exit(&reply, "c", true));
    assert!(exit.check_exit(&syn, "a", true));
    assert!(exit.check_exit(&reply, "a", false));
    assert!(client.check_exit(&reply, "b", true));
    assert!(client.check_exit(&ack, "b", false));
    assert!(exit.check_exit(&ack, "a", true));
    assert!(!client.check_exit(&packet(1,2,40001,8000,2), "b", false));
    assert!(!client.check(&packet(1,2,40001,8000,2), "b", false));
    for target in [[127,0,0,1], [169,254,169,254], [192,168,1,1], [10,203,0,3], [100,100,100,200], [224,0,0,1], [255,255,255,255]] {
        assert!(!client.check_exit(&addressed_packet(local,target,40001,80,2), "b", false));
    }
    let spoof = addressed_packet([10,203,0,3], public, 40002, 443, 2);
    assert!(!exit.check_exit(&spoof, "a", true));
    config.revision += 1; config.exit_routes.clear(); client.apply(config).unwrap();
    assert!(!client.check_exit(&ack, "b", false));
    assert!(!client.check_exit(&reply, "b", true));
}

#[test]
fn exit_traffic_mode_is_enforced_by_client_and_serving_peer() {
    use porthub_mesh::exit_policy::TrafficMode;
    for mode in [TrafficMode::All, TrafficMode::InternetOnly, TrafficMode::LanOnly] {
        let mut config = snapshot();
        config.grants.clear();
        for peer in &mut config.peers { peer.fingerprint = "test-fingerprint".into(); peer.instance = "test-instance".into(); }
        config.exit_routes = serde_json::from_value(json!([{"id":"exit","name":"Exit","routing_peers":["b"],"clients":["a"],"traffic_mode":mode}])).unwrap();
        let mut client = Engine::default(); client.apply(config.clone()).unwrap();
        config.self_ = "b".into();
        let mut exit = Engine::default(); exit.apply(config).unwrap();
        for (target, allowed) in [([8,8,8,8], mode.internet()), ([192,168,80,7], mode.lan()), ([169,254,169,254], false), ([10,203,0,2], false)] {
            let syn = addressed_packet([10,203,0,1], target, 40000, 443, 2);
            assert_eq!(client.check_exit(&syn, "b", false), allowed, "client: {mode:?} {target:?}");
            assert_eq!(exit.check_exit(&syn, "a", true), allowed, "exit: {mode:?} {target:?}");
        }
    }
}

#[test]
fn exit_policies_reject_unknown_peers_overlaps_and_recursive_routing() {
    use porthub_agent::private_network::policy::ExitRoute;
    let route: ExitRoute = serde_json::from_value(json!({"id":"exit", "name":"Internet", "routing_peers":["b"], "clients":["a"]})).unwrap();
    let mut valid = snapshot();
    valid.exit_routes.push(route);
    let mut engine = Engine::default();
    engine.apply(valid.clone()).unwrap();
    for failure in ["unknown", "duplicate", "recursive", "empty"] {
        let mut invalid = valid.clone();
        match failure {
            "unknown" => invalid.exit_routes[0].routing_peers = vec!["unknown".into()],
            "duplicate" => {
                let mut other = invalid.exit_routes[0].clone(); other.id = "other".into();
                invalid.exit_routes.push(other);
            }
            "recursive" => invalid.exit_routes[0].routing_peers.push("a".into()),
            "empty" => invalid.exit_routes[0].clients.clear(),
            _ => unreachable!(),
        }
        assert!(engine.apply(invalid).is_err(), "{failure}");
        assert!(!engine.check(&packet(1, 2, 4000, 8000, 2), "b", false));
        engine.apply(valid.clone()).unwrap();
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
        ("condor.phub.io.", RecordType::A, ResponseCode::NoError, 1),
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

#[test]
fn domain_rules_block_all_record_types_and_restore_when_removed() {
    use hickory_proto::{op::{Message, Query, ResponseCode}, rr::{Name, RecordType}};
    use porthub_mesh::dns_policy::{Action, Rule};
    let mut snapshot = snapshot();
    snapshot.dns_rules = vec![
        Rule { domain: "blocked.example".into(), action: Action::Block, include_subdomains: true },
    ];
    let mut zone = Zone::default(); zone.update(&snapshot).unwrap();
    let answer = |zone: &Zone, name, kind| {
        let mut query = Message::query();
        query.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
        Message::from_vec(&zone.answer(&query.to_vec().unwrap()).unwrap()).unwrap()
    };
    for kind in [RecordType::A, RecordType::AAAA, RecordType::HTTPS, RecordType::TXT] {
        assert_eq!(answer(&zone, "blocked.example", kind).metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(answer(&zone, "www.blocked.example", kind).metadata.response_code, ResponseCode::NXDomain);
    }
    assert_eq!(answer(&zone, "notblocked.example", RecordType::A).metadata.response_code, ResponseCode::Refused);
    snapshot.dns_rules.push(Rule { domain: "miro.phub".into(), action: Action::Block, include_subdomains: true });
    assert!(zone.update(&snapshot).is_err());
    assert_eq!(answer(&zone, "blocked.example", RecordType::A).metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(answer(&zone, "miro.phub", RecordType::A).answers.len(), 1);
    snapshot.dns_rules.clear(); zone.update(&snapshot).unwrap();
    assert_eq!(answer(&zone, "blocked.example", RecordType::A).metadata.response_code, ResponseCode::Refused);
}

#[cfg(all(target_os = "linux", feature = "netns-tests"))]
#[tokio::test]
#[ignore = "requires owned disposable network namespace with writable per-interface sysctls"]
async fn owned_exit_nat_preserves_global_forwarding_and_cleans_up() -> anyhow::Result<()> {
    use anyhow::Context;
    use porthub_agent::private_network::{device::Tun, exit_kernel::Kernel};
    use nlink::netlink::{Connection, Nftables, Route, nftables::Family, route::Ipv4Route, types::route::RouteScope};
    use std::collections::BTreeSet;
    anyhow::ensure!(std::env::var("PORTHUB_TEST_OWNED_NETNS").as_deref() == Ok("1")
        && std::path::Path::new("/.dockerenv").is_file(), "requires owned test container");
    let global = tokio::fs::read("/proc/sys/net/ipv4/ip_forward").await?;
    let own = "10.234.252.1".parse()?;
    let client = "10.234.252.2".parse()?;
    let tun = Tun::open("phab12cd35", own, &[client]).await.context("open owned TUN")?;
    // A second owned TUN acts as the internet-facing link. It allows checking
    // actual NAT and reply translation without sending anything off this host.
    let uplink_ip = "10.234.253.1".parse()?;
    let internet_ip = "10.234.253.2".parse()?;
    let uplink = Tun::open("phab12cd36", uplink_ip, &[internet_ip]).await?;
    Connection::<Route>::new()?.add_route(Ipv4Route::new(std::net::Ipv4Addr::UNSPECIFIED, 0).dev_index(uplink.index).scope(RouteScope::Link)).await?;
    // Reproduce Docker's host forwarding policy without touching host Docker.
    use nlink::netlink::nftables::{config::NftablesConfig, BaseChain, FilterHook, Policy, Priority};
    let docker_nft = Connection::<Nftables>::new()?;
    NftablesConfig::new().table("filter", Family::Ip, |table| table
        .chain("FORWARD", |chain| chain.base(BaseChain::filter(FilterHook::Forward, Priority::Filter).policy(Policy::Drop)))
        .chain("DOCKER-USER", |chain| chain)
        .rule_keyed("FORWARD", "fixture_docker_user", |rule| rule.jump("DOCKER-USER".parse().unwrap()))
        .rule_keyed("DOCKER-USER", "fixture_return", |rule| rule.then(nlink::netlink::nftables::Verdict::Return)))
        .diff(&docker_nft).await?.apply(&docker_nft).await?;
    let original_docker_rules = docker_nft.list_rules("filter", Family::Ip).await?;
    let kernel = Kernel::new(&tun.name)?;
    kernel.apply(&BTreeSet::from([client])).await.context("apply scoped exit NAT")?;
    assert_eq!(tokio::fs::read("/proc/sys/net/ipv4/ip_forward").await?, global);
    assert_eq!(tokio::fs::read_to_string("/proc/sys/net/ipv4/conf/phab12cd35/forwarding").await?.trim(), "1");
    let checksum = |packet: &mut [u8]| {
        packet[10..12].fill(0);
        let mut sum: u32 = packet[..20].as_chunks::<2>().0.iter().map(|bytes| u16::from_be_bytes(*bytes) as u32).sum();
        while sum >> 16 != 0 { sum = (sum & 65535) + (sum >> 16); }
        packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    };
    let mut request = vec![0u8;32];
    request[0]=0x45; request[2..4].copy_from_slice(&32u16.to_be_bytes());
    request[8]=64; request[9]=17;
    request[12..16].copy_from_slice(&client.octets()); request[16..20].copy_from_slice(&internet_ip.octets());
    request[20..22].copy_from_slice(&41000u16.to_be_bytes()); request[22..24].copy_from_slice(&8000u16.to_be_bytes());
    request[24..26].copy_from_slice(&12u16.to_be_bytes()); request[28..].copy_from_slice(b"ping"); checksum(&mut request);
    tun.write(&request).await?;
    let mut forwarded = [0u8;1380];
    let length = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop { let n = uplink.read(&mut forwarded).await?;
            if n >= 28 && forwarded[0] >> 4 == 4 && forwarded[9] == 17 { break Ok::<_,anyhow::Error>(n); }
        }
    }).await??;
    assert_eq!(&forwarded[12..16], &uplink_ip.octets());
    assert_eq!(&forwarded[16..20], &internet_ip.octets());
    assert_eq!(&forwarded[28..length], b"ping");
    for i in 0..4 { forwarded.swap(12+i,16+i); }
    for i in 0..2 { forwarded.swap(20+i,22+i); }
    forwarded[26..28].fill(0); checksum(&mut forwarded[..length]);
    uplink.write(&forwarded[..length]).await?;
    let mut reply=[0u8;1380];
    let length=tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop { let n = tun.read(&mut reply).await?;
            if n >= 28 && reply[0] >> 4 == 4 && reply[9] == 17 { break Ok::<_,anyhow::Error>(n); }
        }
    }).await??;
    assert_eq!(&reply[12..16], &internet_ip.octets());
    assert_eq!(&reply[16..20], &client.octets());
    assert_eq!(&reply[22..24], &41000u16.to_be_bytes());
    assert_eq!(&reply[28..length], b"ping");
    // An unsolicited inbound flow must remain blocked on an underlay whose
    // forwarding was previously disabled.
    forwarded[22..24].copy_from_slice(&41001u16.to_be_bytes());
    forwarded[16..20].copy_from_slice(&client.octets());
    forwarded[26..28].fill(0); checksum(&mut forwarded[..32]);
    uplink.write(&forwarded[..32]).await?;
    assert!(tokio::time::timeout(std::time::Duration::from_millis(150), async {
        loop { let n = tun.read(&mut reply).await?;
            if n >= 28 && reply[0] >> 4 == 4 && reply[9] == 17 { break Ok::<_,anyhow::Error>(n); }
        }
    }).await.is_err());
    let second = Tun::open("phab12cd37", "10.234.254.1".parse()?, &["10.234.254.2".parse()?]).await?;
    let second_kernel = Kernel::new(&second.name)?;
    second_kernel.apply(&BTreeSet::from(["10.234.254.2".parse()?])).await?;
    kernel.clear().await?;
    assert_eq!(tokio::fs::read_to_string("/proc/sys/net/ipv4/conf/phab12cd36/forwarding").await?.trim(), "1");
    second_kernel.clear().await?;
    assert_eq!(tokio::fs::read_to_string("/proc/sys/net/ipv4/conf/phab12cd36/forwarding").await?.trim(), "0");
    drop(second); drop(uplink);
    assert_eq!(tokio::fs::read_to_string("/proc/sys/net/ipv4/conf/phab12cd35/forwarding").await?.trim(), "0");
    assert_eq!(tokio::fs::read("/proc/sys/net/ipv4/ip_forward").await?, global);
    let netlink = Connection::<Nftables>::new()?;
    assert!(!netlink.del_table_if_exists("porthub_exit_phab12cd35", Family::Ip).await?);
    let remaining = docker_nft.list_rules("filter", Family::Ip).await?;
    assert_eq!(remaining.len(), original_docker_rules.len());
    assert_eq!(remaining[0].handle, original_docker_rules[0].handle);
    assert_eq!(remaining[0].expression_bytes, original_docker_rules[0].expression_bytes);
    assert_eq!(remaining[1].handle, original_docker_rules[1].handle);
    assert_eq!(remaining[1].expression_bytes, original_docker_rules[1].expression_bytes);
    let forward = docker_nft.list_chains_in("filter", Family::Ip).await?.into_iter().find(|chain| chain.name == "FORWARD").unwrap();
    assert_eq!(forward.policy, Some(0), "Docker forwarding policy must stay DROP");
    drop(tun);
    Ok(())
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
    assert_eq!(paths.choose(new, true, false), Some(true));
    assert_eq!(paths.choose(new, true, true), Some(true));
}

#[test]
fn path_preferences_only_choose_new_flows_and_keep_available_fallbacks() {
    use porthub_agent::private_network::{paths::Pinned, policy::Packet};
    let gateway_flow = Packet::parse(&packet(1, 2, 5000, 8000, 2)).unwrap();
    let direct_flow = Packet::parse(&packet(1, 2, 5001, 8000, 2)).unwrap();
    let mut paths = Pinned::default();
    assert_eq!(
        paths.choose_preferred(gateway_flow, true, true, false),
        Some(false)
    );
    assert_eq!(
        paths.choose_preferred(gateway_flow, true, true, true),
        Some(false)
    );
    assert_eq!(
        paths.choose_preferred(gateway_flow, true, false, false),
        Some(true)
    );
    assert_eq!(
        paths.choose_preferred(gateway_flow, true, true, false),
        Some(true)
    );
    assert_eq!(
        paths.choose_preferred(direct_flow, true, true, true),
        Some(true)
    );
    assert_eq!(
        paths.choose_preferred(direct_flow, true, true, false),
        Some(true)
    );
    let unavailable_gateway = Packet::parse(&packet(1, 2, 5002, 8000, 2)).unwrap();
    assert_eq!(
        paths.choose_preferred(unavailable_gateway, true, false, false),
        Some(true)
    );
    let unavailable_direct = Packet::parse(&packet(1, 2, 5003, 8000, 2)).unwrap();
    assert_eq!(
        paths.choose_preferred(unavailable_direct, false, true, true),
        Some(false)
    );
    let unavailable_both = Packet::parse(&packet(1, 2, 5004, 8000, 2)).unwrap();
    assert_eq!(
        paths.choose_preferred(unavailable_both, false, false, true),
        None
    );
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
    policy.dns_rules = vec![
        porthub_mesh::dns_policy::Rule { domain: "blocked.ph-policy-test".into(), action: porthub_mesh::dns_policy::Action::Block, include_subdomains: true },
    ];
    server.zone.write().await.update(&policy)?;
    let cancel = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(server.serve(cancel.clone()));
    dns::register(
        tun.index,
        Ipv4Addr::new(10, 234, 251, 1),
        port,
        &["ph-native-test".to_owned(), "blocked.ph-policy-test".to_owned()],
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
    type ResolvedAddresses = Vec<(i32, i32, Vec<u8>)>;
    let (addresses, _, _): (ResolvedAddresses, String, u64) = tokio::time::timeout(
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
    let blocked: std::result::Result<(ResolvedAddresses, String, u64), _> = tokio::time::timeout(
        Duration::from_secs(8), proxy.call("ResolveHostname", &(0i32, "blocked.ph-policy-test", libc::AF_INET, 0u64)),
    ).await?;
    assert!(format!("{:?}", blocked.unwrap_err()).contains("NXDOMAIN"), "blocking must return a DNS policy response");
    cancel.cancel();
    task.await??;
    drop(tun);
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "netns-tests"))]
#[tokio::test]
#[ignore = "requires owned disposable network namespace"]
async fn owned_exit_consumer_routes_new_connections_and_preserves_underlay_sockets() -> anyhow::Result<()> {
    use nlink::netlink::{Connection, Route, route::Ipv4Route, types::route::RouteScope};
    use porthub_agent::private_network::{device::Tun, exit_routes::Consumer};
    use std::{collections::BTreeSet, net::Ipv4Addr, time::Duration};
    anyhow::ensure!(std::env::var("PORTHUB_TEST_OWNED_NETNS").as_deref() == Ok("1")
        && std::path::Path::new("/.dockerenv").is_file(), "requires owned test container");
    let overlay: Ipv4Addr = "10.234.251.1".parse()?;
    let external: Ipv4Addr = "10.234.252.1".parse()?;
    let tun = Tun::open("phab12cd41", overlay, &[]).await?;
    let uplink = Tun::open("phab12cd42", external, &[]).await?;
    let netlink = Connection::<Route>::new()?;
    netlink.set_link_down(&uplink.name).await?;
    netlink.set_link_name_by_index(uplink.index, "enphcontrol").await?;
    netlink.set_link_up("enphcontrol").await?;
    netlink.add_route(Ipv4Route::new(Ipv4Addr::UNSPECIFIED, 0).dev_index(uplink.index).prefsrc(external).scope(RouteScope::Link)).await?;
    async fn receive(tun: &Tun) -> anyhow::Result<Vec<u8>> {
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut packet = vec![0; 1380];
            loop {
                let length = tun.read(&mut packet).await?;
                if length >= 28 && packet[0] >> 4 == 4 && packet[9] == 17 {
                    packet.truncate(length); return Ok(packet);
                }
            }
        }).await?
    }
    let established = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    established.connect("8.8.8.8:8000").await?;
    established.send(b"before").await?;
    assert_eq!(&receive(&uplink).await?[12..16], &external.octets());
    let underlay = BTreeSet::from([external]);
    let mut route = Consumer::activate(tun.index, overlay, &underlay).await?;
    assert!(Consumer::activate(tun.index, overlay, &underlay).await.is_err());
    established.send(b"existing").await?;
    assert_eq!(&receive(&uplink).await?[12..16], &external.octets());
    let new = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    new.send_to(b"exit", "8.8.8.8:8000").await?;
    let packet = receive(&tun).await?;
    assert_eq!(&packet[12..16], &overlay.octets());
    assert_eq!(&packet[28..], b"exit");
    // A fresh gateway request must escape through the physical source even
    // while new application traffic goes into the nonresponding exit TUN.
    let control = porthub_agent::control::Control::new(serde_json::from_value(json!({
        "server":"http://8.8.8.8:8001", "machine_id":"0123456789abcdef01234567",
        "token":"isolated-test", "allow_insecure_http_for_tests":true
    }))?)?;
    let heartbeat = tokio::spawn(async move { control.request(reqwest::Method::POST, "machines/client/sync", None, &[]).await });
    let mut syn = vec![0;1380];
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let length = uplink.read(&mut syn).await?;
            if length >= 40 && syn[0] >> 4 == 4 && syn[9] == 6 && syn[22..24] == 8001u16.to_be_bytes() {
                assert_eq!(&syn[12..16], &external.octets());
                break Ok::<_, anyhow::Error>(());
            }
        }
    }).await??;
    heartbeat.abort();
    let _ = heartbeat.await;
    // Public tunnel control/data transports also bypass the dead exit, using
    // the same source binding as scheduled endpoint reachability checks.
    let mut plan = porthub_tunnel::client_plan::ClientPlan::parse(
        "[client]\nremote_addr='ws://8.8.8.8:8002/api/tunnel'\n[client.services.test]\ntoken='isolated-test'\nlocal_addr='127.0.0.1:22'\n"
    )?;
    plan.bind_source(external.into());
    let candidate = plan.candidates.remove(0);
    let probe = tokio::spawn(async move { candidate.probe(Duration::from_secs(10)).await });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let length = uplink.read(&mut syn).await?;
            if length >= 40 && syn[0] >> 4 == 4 && syn[9] == 6 && syn[22..24] == 8002u16.to_be_bytes() {
                assert_eq!(&syn[12..16], &external.octets());
                break Ok::<_, anyhow::Error>(());
            }
        }
    }).await??;
    probe.abort();
    let _ = probe.await;
    let pinned_exit = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    pinned_exit.connect("8.8.8.8:8000").await?;
    route.set_bypass(true).await?;
    pinned_exit.send(b"exit flow must stay on its original path").await?;
    assert_eq!(&receive(&tun).await?[12..16], &overlay.octets());
    let fallback = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    fallback.connect("8.8.8.8:8000").await?;
    fallback.send(b"new direct fallback").await?;
    assert_eq!(&receive(&uplink).await?[12..16], &external.octets());
    route.set_bypass(false).await?;
    fallback.send(b"direct connection survives exit recovery").await?;
    assert_eq!(&receive(&uplink).await?[12..16], &external.octets());
    let recovered_exit = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    recovered_exit.send_to(b"new connections use the exit again", "8.8.8.8:8000").await?;
    assert_eq!(&receive(&tun).await?[12..16], &overlay.octets());
    let control = tokio::net::UdpSocket::bind((external, 0)).await?;
    control.send_to(b"control", "8.8.8.8:8000").await?;
    assert_eq!(&receive(&uplink).await?[12..16], &external.octets());
    let additional: Ipv4Addr = "10.234.252.2".parse()?;
    netlink.add_address_by_index(uplink.index, additional.into(), 32).await?;
    route.refresh(&BTreeSet::from([external, additional])).await?;
    let new_control = tokio::net::UdpSocket::bind((additional, 0)).await?;
    new_control.send_to(b"new interface address", "8.8.8.8:8000").await?;
    assert_eq!(&receive(&uplink).await?[12..16], &additional.octets());
    route.refresh(&BTreeSet::from([external])).await?;
    established.send(b"still connected").await?;
    assert_eq!(&receive(&uplink).await?[12..16], &external.octets());
    route.clear().await?;
    let after = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    after.send_to(b"restored", "8.8.8.8:8000").await?;
    assert_eq!(&receive(&uplink).await?[12..16], &external.octets());
    assert!(!netlink.get_rules_v4().await?.iter().any(|rule| (22500..=22600).contains(&rule.priority())));
    let (wanted, desired) = tokio::sync::watch::channel(None);
    let (_addresses, interfaces) = tokio::sync::watch::channel(vec![std::net::SocketAddr::new(external.into(), 0)]);
    let cancel = tokio_util::sync::CancellationToken::new();
    let (report, mut applied) = tokio::sync::watch::channel("pending");
    let owner = tokio::spawn(porthub_agent::private_network::exit_routes::watch_reported(desired, interfaces, cancel.clone(), Some(report)));
    wanted.send_replace(Some((tun.index, overlay, false)));
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if netlink.get_rules_v4().await?.iter().any(|rule| rule.priority() == 22600) { break Ok::<_,anyhow::Error>(()); }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await??;
    tokio::time::timeout(Duration::from_secs(2), async {
        while *applied.borrow_and_update() != "exit routing active" { applied.changed().await?; }
        Ok::<_, anyhow::Error>(())
    }).await??;
    let watched = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    watched.send_to(b"background owner", "8.8.8.8:8000").await?;
    assert_eq!(&receive(&tun).await?[12..16], &overlay.octets());
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), owner).await???;
    assert_eq!(*applied.borrow(), "inactive");
    assert!(!netlink.get_rules_v4().await?.iter().any(|rule| (22500..=22600).contains(&rule.priority())));
    let sentinel = nlink::netlink::rule::RuleBuilder::v4().priority(20000).protocol(99).from_prefix("192.0.2.99",32).table(254);
    netlink.add_rule(sentinel.clone()).await?;
    let crashed_tun = Tun::open("phab12cd43", "10.234.250.1".parse()?, &[]).await?;
    let crashed = Consumer::activate(crashed_tun.index, "10.234.250.1".parse()?, &underlay).await?;
    drop(crashed); drop(crashed_tun);
    let mut recovered = Consumer::activate(tun.index, overlay, &underlay).await?;
    let recovered_socket = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    recovered_socket.send_to(b"recovered", "8.8.8.8:8000").await?;
    assert_eq!(&receive(&tun).await?[12..16], &overlay.octets());
    recovered.clear().await?; recovered.clear().await?;
    assert!(netlink.get_rules_v4().await?.iter().any(|rule| rule.priority() == 20000 && rule.protocol() == Some(99)));
    netlink.del_rule(sentinel).await?;
    assert!(!std::path::Path::new("/run/porthub-exits/consumer.json").exists());
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "netns-tests"))]
#[tokio::test]
#[ignore = "requires owned disposable network namespace"]
async fn owned_exit_ipv6_guard_blocks_new_internet_connections_and_restores_routes() -> anyhow::Result<()> {
    use nlink::netlink::{Connection, Route, Nftables, route::Ipv6Route, nftables::{config::NftablesConfig, Family, BaseChain, FilterHook, Priority, CtState}};
    use porthub_agent::private_network::{device::Tun, exit_routes::Consumer};
    use std::{collections::BTreeSet, net::{Ipv4Addr, Ipv6Addr}, time::Duration};
    anyhow::ensure!(std::env::var("PORTHUB_TEST_OWNED_NETNS").as_deref() == Ok("1") && std::path::Path::new("/.dockerenv").is_file(), "requires owned test container");
    let netlink = Connection::<Route>::new()?;
    let wire = Tun::open("phab12cd62", "10.234.252.1".parse()?, &[]).await?;
    let index = wire.index;
    let source: Ipv6Addr = "2001:db8:1::1".parse()?;
    let destination: Ipv6Addr = "2001:db8:2::1".parse()?;
    netlink.add_address_by_index(index, source.into(), 64).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    netlink.add_route(Ipv6Route::new(Ipv6Addr::UNSPECIFIED, 0).dev_index(index).prefsrc(source)).await?;
    assert!(netlink.lookup_route(destination.into()).await.is_ok());
    // Ensure conntrack observes traffic before enabling the consumer, as it
    // does on a host with a stateful firewall. This table never blocks traffic.
    let nft = Connection::<Nftables>::new()?;
    let tracking = NftablesConfig::new().table("exit_test_tracking", Family::Ip6, |table| table
        .chain("output", |chain| chain.base(BaseChain::filter(FilterHook::Output, Priority::Filter)).exclusive())
        .rule_keyed("output", "track", |rule| rule.match_ct_state(CtState::ESTABLISHED).accept()));
    tracking.diff(&nft).await?.apply(&nft).await?;
    async fn echo(wire: &Tun) -> anyhow::Result<()> {
        let mut packet = [0u8; 1500];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(2), wire.read(&mut packet)).await??;
            if n < 48 || packet[0] >> 4 != 6 || packet[6] != 17 { continue; }
            // Swapping both endpoints leaves the UDP pseudoheader checksum valid.
            for i in 0..16 { packet.swap(8+i, 24+i); }
            packet.swap(40, 42); packet.swap(41, 43);
            wire.write(&packet[..n]).await?;
            return Ok(());
        }
    }
    let established = tokio::net::UdpSocket::bind((source, 0)).await?;
    established.connect((destination, 8000)).await?;
    established.send(b"before activation").await?;
    echo(&wire).await?;
    let mut reply = [0u8; 64];
    let size = tokio::time::timeout(Duration::from_secs(2), established.recv(&mut reply)).await??;
    assert_eq!(&reply[..size], b"before activation");
    let tun = Tun::open("phab12cd61", "10.234.250.1".parse()?, &[]).await?;
    let mut policy = Consumer::activate(tun.index, "10.234.250.1".parse()?, &BTreeSet::from([Ipv4Addr::new(192,0,2,1)])).await?;
    nft.del_table_if_exists("exit_test_tracking", Family::Ip6).await?;
    established.send(b"existing flow survives").await?;
    echo(&wire).await?;
    let size = tokio::time::timeout(Duration::from_secs(2), established.recv(&mut reply)).await??;
    assert_eq!(&reply[..size], b"existing flow survives");
    let fresh = tokio::net::UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).await?;
    fresh.connect((destination, 8000)).await?;
    assert!(fresh.send(b"must not bypass the exit").await.is_err(), "new IPv6 traffic escaped");
    let control = tokio::net::UdpSocket::bind((source, 0)).await?;
    control.connect((destination, 8000)).await?;
    assert!(control.send(b"bound sockets cannot bypass either").await.is_err());
    policy.set_bypass(true).await?;
    let bypass = tokio::net::UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).await?;
    bypass.connect((destination, 8000)).await?;
    bypass.send(b"normal IPv6 during authorized fallback").await?;
    echo(&wire).await?;
    tokio::time::timeout(Duration::from_secs(2), bypass.recv(&mut reply)).await??;
    policy.set_bypass(false).await?;
    bypass.send(b"established fallback survives recovery").await?;
    echo(&wire).await?;
    tokio::time::timeout(Duration::from_secs(2), bypass.recv(&mut reply)).await??;
    let blocked_again = tokio::net::UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).await?;
    blocked_again.connect((destination, 8000)).await?;
    assert!(blocked_again.send(b"new IPv6 blocked after recovery").await.is_err());
    let lan = tokio::net::UdpSocket::bind((source, 0)).await?;
    lan.send_to(b"local IPv6 remains available", ("2001:db8:1::2".parse::<Ipv6Addr>()?, 8000)).await?;
    policy.clear().await?;
    let restored = tokio::net::UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).await?;
    restored.send_to(b"normal IPv6 restored", (destination, 8000)).await?;
    assert!(netlink.lookup_route(destination.into()).await.is_ok());
    assert!(!netlink.get_rules_v6().await?.iter().any(|rule| (22500..=22600).contains(&rule.priority())));
    nft.del_table_if_exists("exit_test_tracking", Family::Ip6).await?;
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "netns-tests"))]
#[tokio::test]
#[ignore = "requires an explicitly owned disposable network namespace"]
async fn container_forwarding_uses_host_exit_and_pins_flows_across_fallback() -> anyhow::Result<()> {
    use anyhow::{ensure, Context};
    use std::{collections::BTreeSet, net::Ipv4Addr, time::Duration as StdDuration};
    use porthub_agent::private_network::{device::Tun, exit_routes::Consumer};
    use nlink::netlink::{Connection, Nftables, Route, route::Ipv4Route, types::route::RouteScope,
        nftables::{config::NftablesConfig, BaseChain, Family, FilterHook, Policy, Priority}};
    ensure!(std::env::var("PORTHUB_TEST_OWNED_NETNS").as_deref() == Ok("1") && std::path::Path::new("/.dockerenv").is_file(), "requires owned disposable container");
    let routes = Connection::<Route>::new()?;
    let exit_ip: Ipv4Addr = "10.234.251.1".parse()?;
    let underlay_ip: Ipv4Addr = "10.234.253.1".parse()?;
    let client: Ipv4Addr = "172.28.251.2".parse()?;
    let internet: Ipv4Addr = "203.0.113.90".parse()?;
    let exit = Tun::open("phab12cd51", exit_ip, &[]).await?;
    let underlay = Tun::open("phab12cd52", underlay_ip, &[]).await?;
    let bridge = Tun::open("phab12cd53", "172.28.251.1".parse()?, &[client]).await?;
    // A TUN named like Docker's bridge injects real forwarded IP packets without
    // creating nested containers or changing any host Docker/firewall resources.
    routes.set_link_name_by_index(bridge.index, "br-phubtest").await?;
    tokio::fs::write("/proc/sys/net/ipv4/conf/br-phubtest/forwarding", b"1\n").await?;
    routes.add_route(Ipv4Route::new(Ipv4Addr::UNSPECIFIED, 0).dev_index(underlay.index).scope(RouteScope::Link)).await?;
    let nft = Connection::<Nftables>::new()?;
    NftablesConfig::new().table("filter", Family::Ip, |table| table
        .chain("FORWARD", |chain| chain.base(BaseChain::filter(FilterHook::Forward, Priority::Filter).policy(Policy::Drop)))
        .chain("DOCKER-USER", |chain| chain)
        .rule_keyed("FORWARD", "docker", |rule| rule.jump("DOCKER-USER".parse().unwrap()))
        .rule_keyed("DOCKER-USER", "original_uplink", |rule| rule.match_oif(&underlay.name).accept())
        .rule_keyed("DOCKER-USER", "published_port", |rule| rule.match_iif(&underlay.name).match_oif("br-phubtest").accept())
        .rule_keyed("DOCKER-USER", "return", |rule| rule.then(nlink::netlink::nftables::Verdict::Return)))
        .diff(&nft).await?.apply(&nft).await?;
    let original_rules = nft.list_rules("filter", Family::Ip).await?;
    let mut owner = Consumer::activate(exit.index, exit_ip, &BTreeSet::from([underlay_ip])).await?;
    fn udp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
        let mut p = vec![0u8; 32]; p[0] = 0x45; p[2..4].copy_from_slice(&32u16.to_be_bytes()); p[8] = 64; p[9] = 17;
        p[12..16].copy_from_slice(&src.octets()); p[16..20].copy_from_slice(&dst.octets());
        p[20..22].copy_from_slice(&sport.to_be_bytes()); p[22..24].copy_from_slice(&dport.to_be_bytes()); p[24..26].copy_from_slice(&12u16.to_be_bytes()); p[28..].copy_from_slice(b"test");
        let mut sum: u32 = p[..20].as_chunks::<2>().0.iter().map(|bytes| u16::from_be_bytes(*bytes) as u32).sum();
        while sum >> 16 != 0 { sum = (sum & 65535) + (sum >> 16); }
        p[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes()); p
    }
    async fn read(tun: &Tun) -> anyhow::Result<Vec<u8>> {
        let mut bytes = vec![0u8; 2048];
        tokio::time::timeout(StdDuration::from_secs(3), async {
            loop {
                let size = tun.read(&mut bytes).await?;
                // Kernel IPv6 link-local solicitation is unrelated to the IPv4
                // flow under test and can appear immediately after TUN setup.
                if size >= 28 && bytes[0] >> 4 == 4 && bytes[9] == 17 {
                    bytes.truncate(size); return Ok::<_, anyhow::Error>(bytes);
                }
            }
        }).await.context("forwarded packet did not reach expected interface")?
    }
    // A published-port request arrived through the ordinary uplink. Its
    // container reply must not unexpectedly change its source exit identity.
    tokio::fs::write(format!("/proc/sys/net/ipv4/conf/{}/forwarding", underlay.name), b"1\n").await?;
    underlay.write(&udp(internet, client, 9000, 45104)).await?;
    ensure!(&read(&bridge).await?[16..20] == client.octets(), "incoming published-port request did not reach container");
    bridge.write(&udp(client, internet, 45104, 9000)).await?;
    ensure!(&read(&underlay).await?[12..16] == client.octets(), "published-port reply was diverted through exit");
    bridge.write(&udp(client, internet, 45101, 9000)).await?;
    let outgoing = read(&exit).await?;
    ensure!(&outgoing[12..16] == exit_ip.octets(), "container source was not translated to enrolled host: {:?}", &outgoing[..outgoing.len().min(32)]);
    let source_port = u16::from_be_bytes([outgoing[20], outgoing[21]]);
    exit.write(&udp(internet, exit_ip, 9000, source_port)).await?;
    let reply = read(&bridge).await?;
    ensure!(&reply[16..20] == client.octets(), "reply was not restored to original container");
    owner.set_bypass(true).await?;
    bridge.write(&udp(client, internet, 45101, 9000)).await?;
    ensure!(&read(&exit).await?[12..16] == exit_ip.octets(), "existing container exit flow moved during fallback");
    bridge.write(&udp(client, internet, 45102, 9000)).await?;
    ensure!(&read(&underlay).await?[12..16] == client.octets(), "new fallback connection did not use underlay");
    owner.set_bypass(false).await?;
    bridge.write(&udp(client, internet, 45102, 9000)).await?;
    ensure!(&read(&underlay).await?[12..16] == client.octets(), "existing direct container flow moved on recovery");
    bridge.write(&udp(client, internet, 45103, 9000)).await?;
    ensure!(&read(&exit).await?[12..16] == exit_ip.octets(), "new container connection did not resume exit");
    let remote_lan:Ipv4Addr="10.80.0.7".parse()?;
    bridge.write(&udp(client, remote_lan, 45105, 9000)).await?;
    ensure!(&read(&underlay).await?[12..16] == client.octets(), "internet-only captured private traffic");
    owner.set_lan_networks(&["10.80.0.0/16".parse()?]).await?;
    owner.set_bypass(true).await?;
    bridge.write(&udp(client, remote_lan, 45106, 9000)).await?;
    ensure!(&read(&exit).await?[12..16] == exit_ip.octets(), "LAN-only did not select an authorized private destination");
    bridge.write(&udp(client, internet, 45107, 9000)).await?;
    ensure!(&read(&underlay).await?[12..16] == client.octets(), "LAN-only captured internet traffic");
    bridge.write(&udp(client, remote_lan, 45105, 9000)).await?;
    ensure!(&read(&underlay).await?[12..16] == client.octets(), "existing private connection moved after enabling LAN routing");
    bridge.write(&udp(client, internet, 45103, 9000)).await?;
    ensure!(&read(&exit).await?[12..16] == exit_ip.octets(), "existing internet exit connection moved after selecting LAN-only");
    owner.clear().await?;
    let remaining = nft.list_rules("filter", Family::Ip).await?;
    ensure!(remaining.len() == original_rules.len() && original_rules.iter().all(|old| remaining.iter().any(|rule| rule.handle == old.handle && rule.nft_syntax() == old.nft_syntax())), "container cleanup changed foreign Docker rules");
    ensure!(routes.get_rules_v4().await?.iter().all(|rule| !(22500..=22600).contains(&rule.priority())), "container route rules leaked after cleanup");
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "netns-tests"))]
#[tokio::test]
#[ignore = "requires explicitly owned disposable network namespace"]
async fn lan_only_routes_remote_subnets_and_preserves_local_and_internet_routes() -> anyhow::Result<()> {
    use nlink::netlink::{Connection, Route, route::Ipv4Route, types::route::RouteScope};
    use porthub_agent::private_network::device::Tun;
    use std::{net::Ipv4Addr, time::Duration};
    anyhow::ensure!(std::env::var("PORTHUB_TEST_OWNED_NETNS").as_deref() == Ok("1")
        && std::path::Path::new("/.dockerenv").is_file(), "requires owned test container");
    let overlay: Ipv4Addr = "10.234.251.1".parse()?;
    let physical: Ipv4Addr = "10.234.252.1".parse()?;
    let tun = Tun::open("phab12cd51", overlay, &[]).await?;
    let uplink = Tun::open("phab12cd52", physical, &[]).await?;
    let netlink = Connection::<Route>::new()?;
    netlink.add_route(Ipv4Route::new(Ipv4Addr::UNSPECIFIED, 0).dev_index(uplink.index).prefsrc(physical).scope(RouteScope::Link)).await?;
    netlink.add_route(Ipv4Route::new("192.168.0.0".parse()?, 16).dev_index(uplink.index).prefsrc(physical).scope(RouteScope::Link)).await?;
    // A narrower remote advertisement cannot take over the existing local LAN.
    tun.update_lan_routes(&["192.168.80.0/24".parse()?, "10.80.0.0/24".parse()?]).await?;
    async fn send_and_receive(destination: &str, device: &Tun, source: Ipv4Addr) -> anyhow::Result<()> {
        let socket = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
        socket.send_to(b"lan-mode", destination).await?;
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut packet = [0u8; 1380];
            loop {
                let size = device.read(&mut packet).await?;
                if size >= 36 && packet[0] >> 4 == 4 && packet[9] == 17 {
                    assert_eq!(&packet[12..16], &source.octets());
                    assert_eq!(&packet[28..size], b"lan-mode");
                    return Ok::<_, anyhow::Error>(());
                }
            }
        }).await??;
        Ok(())
    }
    send_and_receive("10.80.0.7:8000", &tun, overlay).await?;
    send_and_receive("192.168.80.7:8000", &uplink, physical).await?;
    send_and_receive("8.8.8.8:8000", &uplink, physical).await?;
    tun.update_lan_routes(&[]).await?;
    send_and_receive("10.80.0.7:8000", &uplink, physical).await?;
    Ok(())
}

#[cfg(all(target_os="linux",feature="netns-tests"))]
#[tokio::test]
#[ignore="requires explicitly owned disposable network namespace"]
async fn lan_policy_keeps_main_routes_and_physical_control_connections_unchanged()->anyhow::Result<()> {
    use nlink::netlink::{Connection,Route,route::Ipv4Route,types::route::RouteScope};
    use porthub_agent::private_network::{device::Tun,exit_routes::Consumer};
    use std::{collections::BTreeSet,net::Ipv4Addr,time::Duration};
    anyhow::ensure!(std::env::var("PORTHUB_TEST_OWNED_NETNS").as_deref()==Ok("1") && std::path::Path::new("/.dockerenv").is_file(),"requires owned test container");
    let own:Ipv4Addr="10.234.251.1".parse()?;let physical:Ipv4Addr="10.234.252.1".parse()?;
    let tun=Tun::open("phab12cd71",own,&[]).await?;
    let uplink=Tun::open("phab12cd72",physical,&[]).await?;
    let netlink=Connection::<Route>::new()?;
    netlink.add_route(Ipv4Route::new(Ipv4Addr::UNSPECIFIED,0).dev_index(uplink.index).prefsrc(physical).scope(RouteScope::Link)).await?;
    netlink.add_route(Ipv4Route::new("192.168.86.0".parse()?,24).dev_index(uplink.index).prefsrc(physical).scope(RouteScope::Link)).await?;
    let mut before:Vec<_>=netlink.get_routes_for_table(254).await?.iter().filter(|route|route.is_ipv4()).map(|route|(route.destination().cloned(),route.dst_len(),route.oif(),route.prefsrc().cloned())).collect();before.sort();
    let mut policy=Consumer::activate_with_bypass(tun.index,own,&BTreeSet::from([physical]),true).await?;
    let networks=["10.0.0.0/8".parse()?,"172.16.0.0/12".parse()?,"192.168.0.0/16".parse()?];
    policy.set_lan_networks(&networks).await?;policy.set_lan_networks(&networks).await?;
    assert_eq!(netlink.get_rules_v4().await?.iter().filter(|rule|rule.priority()==22568 && rule.protocol()==Some(186)).count(),3);
    async fn receive(device:&Tun,source:Ipv4Addr)->anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(2),async {
            let mut packet=[0u8;1380];
            loop {
                let size=device.read(&mut packet).await?;
                if size>=32 && packet[0]>>4==4 && packet[9]==17 {
                    assert_eq!(&packet[12..16],&source.octets());assert_eq!(&packet[28..size],b"test");return Ok::<_,anyhow::Error>(());
                }
            }
        }).await??;Ok(())
    }
    for (target,device,source) in [
        ("10.80.0.7:8000",&tun,own),
        ("192.168.0.153:8000",&tun,own),
        ("192.168.86.7:8000",&uplink,physical),
        ("8.8.8.8:8000",&uplink,physical),
    ] {
        let socket=tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED,0)).await?;
        socket.send_to(b"test",target).await?;receive(device,source).await?;
    }
    let control=tokio::net::UdpSocket::bind((physical,0)).await?;
    control.send_to(b"test","10.80.0.7:8000").await?;receive(&uplink,physical).await?;
    let mut after:Vec<_>=netlink.get_routes_for_table(254).await?.iter().filter(|route|route.is_ipv4()).map(|route|(route.destination().cloned(),route.dst_len(),route.oif(),route.prefsrc().cloned())).collect();after.sort();assert_eq!(before,after);
    policy.set_lan_networks(&[]).await?;
    let socket=tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED,0)).await?;
    socket.send_to(b"test","10.80.0.7:8000").await?;receive(&uplink,physical).await?;
    // Internet-only must leave private destinations behind the ordinary
    // router reachable, while still selecting the exit for public traffic.
    policy.set_bypass(false).await?;
    let socket=tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED,0)).await?;
    socket.send_to(b"test","10.80.0.7:8000").await?;receive(&uplink,physical).await?;
    let socket=tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED,0)).await?;
    socket.send_to(b"test","8.8.8.8:8000").await?;receive(&tun,own).await?;
    policy.clear().await?;
    assert!(!netlink.get_rules_v4().await?.iter().any(|rule|(22500..=22600).contains(&rule.priority())));
    let (desired,receiver)=tokio::sync::watch::channel(None);
    let (_sources,interfaces)=tokio::sync::watch::channel(vec![std::net::SocketAddr::from((physical,0))]);
    let cancel=tokio_util::sync::CancellationToken::new();
    let (report,mut state)=tokio::sync::watch::channel("pending");
    let worker=tokio::spawn(porthub_agent::private_network::exit_routes::watch_plans_reported(receiver,interfaces,cancel.clone(),Some(report)));
    desired.send_replace(Some(porthub_agent::private_network::exit_plan::Plan {
        index:tun.index,own,mode:porthub_mesh::exit_policy::TrafficMode::LanOnly,bypass:false,networks:networks.to_vec(),
    }));
    tokio::time::timeout(Duration::from_secs(3),async {
        while *state.borrow_and_update()!="LAN routing active" {state.changed().await?;}
        Ok::<_,anyhow::Error>(())
    }).await??;
    let socket=tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED,0)).await?;
    socket.send_to(b"test","10.80.0.7:8000").await?;receive(&tun,own).await?;
    let socket=tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED,0)).await?;
    socket.send_to(b"test","8.8.8.8:8000").await?;receive(&uplink,physical).await?;
    control.send_to(b"test","10.80.0.7:8000").await?;receive(&uplink,physical).await?;
    cancel.cancel();tokio::time::timeout(Duration::from_secs(3),worker).await???;
    assert_eq!(*state.borrow(),"inactive");
    assert!(!netlink.get_rules_v4().await?.iter().any(|rule|(22500..=22600).contains(&rule.priority())));
    Ok(())
}
