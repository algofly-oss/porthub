//! Every shape `WireguardConfig` can declare must converge.
//!
//! The WireGuard diff compares a declaration against `GET_DEVICE`. The
//! kernel does not store everything as it was sent: a private key is
//! X25519-clamped before it is kept, an allowed IP is masked to its
//! prefix, a duplicate allowed IP is one trie node. Each of those makes
//! the next diff non-empty and every later apply rewrite the device or
//! the peer — invisible applying once.
//!
//! Creating a WireGuard device needs root in the initial user namespace,
//! so this file gates on `require_host_root!()` (#357).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use nlink::netlink::genl::wireguard::{AllowedIp, WireguardConfig};

use crate::common::TestNamespace;
use crate::common::converge::{assert_converges, case};

const UNCLAMPED: [u8; 32] = [0xaa; 32];

/// `UNCLAMPED` the way the kernel stores it (curve25519_clamp_secret).
fn clamped(mut key: [u8; 32]) -> [u8; 32] {
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
    key
}

fn peer_key(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn v4_endpoint() -> SocketAddr {
    "203.0.113.1:51820".parse().unwrap()
}

#[tokio::test]
async fn every_wireguard_shape_converges() -> nlink::Result<()> {
    require_root!();
    nlink::require_host_root!();
    nlink::require_modules!("wireguard");

    let cases = vec![
        // The kernel clamps the private key before storing it, and dumps
        // the clamped one.
        case(
            "private-key-unclamped",
            vec![WireguardConfig::new().device("wg0", |d| d.private_key(UNCLAMPED))],
        ),
        case(
            "private-key-clamped",
            vec![WireguardConfig::new().device("wg0", |d| d.private_key(clamped(UNCLAMPED)))],
        ),
        case(
            "listen-port",
            vec![WireguardConfig::new().device("wg0", |d| d.listen_port(51820))],
        ),
        case(
            "fwmark",
            vec![WireguardConfig::new().device("wg0", |d| d.fwmark(0x42))],
        ),
        case(
            "fwmark-0",
            vec![WireguardConfig::new().device("wg0", |d| d.fwmark(0))],
        ),
        // 0 means "kernel, pick one"; the port it picked is never 0.
        case(
            "listen-port-0",
            vec![WireguardConfig::new().device("wg0", |d| {
                d.private_key(UNCLAMPED).listen_port(0)
            })],
        ),
        case(
            "keepalive-0",
            vec![WireguardConfig::new().device("wg0", |d| {
                d.peer(peer_key(0xe1), |p| p.persistent_keepalive(Duration::ZERO))
            })],
        ),
        case(
            "endpoint-v4-to-v6",
            vec![
                WireguardConfig::new().device("wg0", |d| {
                    d.peer(peer_key(0xe2), |p| p.endpoint(v4_endpoint()))
                }),
                WireguardConfig::new().device("wg0", |d| {
                    d.peer(peer_key(0xe2), |p| p.endpoint("[2001:db8::9]:5".parse().unwrap()))
                }),
            ],
        ),
        case(
            "device-fields-together",
            vec![WireguardConfig::new().device("wg0", |d| {
                d.private_key(UNCLAMPED).listen_port(51821).fwmark(7)
            })],
        ),
        case(
            "peer-v4",
            vec![WireguardConfig::new().device("wg0", |d| {
                d.private_key(UNCLAMPED).peer(peer_key(0xb1), |p| {
                    p.endpoint(v4_endpoint())
                        .persistent_keepalive(Duration::from_secs(25))
                        .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24))
                })
            })],
        ),
        // The kernel returns a preshared key to a CAP_NET_ADMIN GET, so it
        // can be compared like the private key.
        case(
            "peer-preshared-key",
            vec![WireguardConfig::new().device("wg0", |d| {
                d.peer(peer_key(0xb2), |p| {
                    p.preshared_key([0x11; 32])
                        .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 1, 0), 24))
                })
            })],
        ),
        case(
            "peer-v6-endpoint-and-allowed-ips",
            vec![WireguardConfig::new().device("wg0", |d| {
                d.peer(peer_key(0xb3), |p| {
                    p.endpoint("[2001:db8::1]:51820".parse().unwrap())
                        .allowed_ip(AllowedIp::v6("fd00:1::".parse().unwrap(), 64))
                        .allowed_ip(AllowedIp::v6(Ipv6Addr::UNSPECIFIED, 0))
                })
            })],
        ),
        // The allowed-IPs trie keeps the prefix, not the host bits.
        case(
            "allowed-ips-with-host-bits",
            vec![WireguardConfig::new().device("wg0", |d| {
                d.peer(peer_key(0xb4), |p| {
                    p.allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 2, 5), 24))
                        .allowed_ip(AllowedIp::v6("fd00:2::5".parse().unwrap(), 64))
                })
            })],
        ),
        // One trie node, however many times it is declared.
        case(
            "allowed-ips-duplicated",
            vec![WireguardConfig::new().device("wg0", |d| {
                d.peer(peer_key(0xb5), |p| {
                    p.allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 3, 0), 24))
                        .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 3, 0), 24))
                })
            })],
        ),
        case(
            "multiple-peers",
            vec![WireguardConfig::new().device("wg0", |d| {
                d.private_key(UNCLAMPED)
                    .listen_port(51822)
                    .peer(peer_key(0xc1), |p| {
                        p.endpoint(v4_endpoint())
                            .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 1, 1, 0), 24))
                    })
                    .peer(peer_key(0xc2), |p| {
                        p.endpoint("203.0.113.2:51820".parse().unwrap())
                            .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 1, 2, 0), 24))
                    })
                    .peer(peer_key(0xc3), |p| {
                        p.allowed_ip(AllowedIp::v6("fd00:3::".parse().unwrap(), 64))
                    })
            })],
        ),
        case(
            "peer-removed",
            vec![
                WireguardConfig::new().device("wg0", |d| {
                    d.peer(peer_key(0xd1), |p| {
                        p.endpoint(v4_endpoint())
                            .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 2, 1, 0), 24))
                    })
                    .peer(peer_key(0xd2), |p| {
                        p.allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 2, 2, 0), 24))
                    })
                }),
                WireguardConfig::new().device("wg0", |d| {
                    d.peer(peer_key(0xd1), |p| {
                        p.allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 2, 1, 0), 24))
                    })
                }),
            ],
        ),
    ];
    assert_converges("wge", cases).await
}

/// A `wg-quick` profile as people write them: an unclamped private key
/// (whatever `wg genkey` printed is already clamped, but a hand-made or
/// derived one need not be), a preshared key, host bits in AllowedIPs.
#[tokio::test]
async fn wg_quick_profile_converges() -> nlink::Result<()> {
    require_root!();
    nlink::require_host_root!();
    nlink::require_modules!("wireguard");

    // 0xaa * 32, 0xbb * 32 and 0x11 * 32 in base64.
    let profile = "\
[Interface]
PrivateKey = qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=
ListenPort = 51823
FwMark = 0x10
Address = 10.200.0.1/24

[Peer]
PublicKey = u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s=
PresharedKey = ERERERERERERERERERERERERERERERERERERERERERE=
Endpoint = 198.51.100.7:51820
AllowedIPs = 10.200.0.2/32, 10.201.0.9/16, fd00:200::1/64
PersistentKeepalive = 15
";
    let cfg = WireguardConfig::from_wg_quick("wg0", profile)?;
    assert_converges("wge", vec![case("wg-quick", vec![cfg])]).await
}

/// One allowed-IP prefix on two peers of a device is refused before
/// anything is written. The kernel gives a prefix to one peer, so writing
/// it on the second took it from the first, and every apply rewrote every
/// peer — a hub declaring each spoke with the tunnel /24 (#498).
#[tokio::test]
async fn a_prefix_on_two_peers_is_refused() -> nlink::Result<()> {
    require_root!();
    nlink::require_host_root!();
    nlink::require_modules!("wireguard");

    let ns = TestNamespace::new("wge-shared")?;
    let tunnel = AllowedIp::v4(Ipv4Addr::new(10, 99, 0, 0), 24);
    let cfg = WireguardConfig::new().device("wg0", |d| {
        d.private_key(UNCLAMPED)
            .peer(peer_key(0xb1), |p| p.allowed_ip(tunnel))
            .peer(peer_key(0xb2), |p| p.allowed_ip(tunnel))
    });
    cfg.ensure_devices(&ns.connection()?).await?;
    let wg = ns
        .connection_for_async::<nlink::netlink::Wireguard>()
        .await?;
    let err = cfg.apply(&wg).await.unwrap_err();
    assert!(err.to_string().contains("allowed IP of two peers"), "{err}");
    let device = wg.get_device_by_name("wg0").await?;
    assert!(device.peers.is_empty(), "nothing was written: {device:?}");
    Ok(())
}

/// #500: all peers went into one `WGDEVICE_A_PEERS` nest, whose u16
/// `nla_len` cannot describe ~400 peers, or ~1,600 IPv6 allowed-ips on one
/// peer — a debug-build panic, a malformed message in release. Now it is
/// split the way wg(8) splits it, and the kernel ends up with every peer
/// and every allowed-ip.
#[tokio::test]
async fn a_large_peer_set_reaches_the_kernel_whole() -> nlink::Result<()> {
    use nlink::netlink::genl::wireguard::WgPeerBuilder;
    use nlink::netlink::link::WireguardLink;
    use nlink::netlink::Wireguard;
    require_root!();
    nlink::require_host_root!();
    nlink::require_module!("wireguard");

    let ns = TestNamespace::new("wg-many")?;
    ns.connection()?
        .add_link(WireguardLink::new("wgm0"))
        .await?;
    let wg = nlink::Connection::<Wireguard>::new_in_async(ns.name()).await?;
    let key = |n: u32| {
        let mut k = [0u8; 32];
        k[..4].copy_from_slice(&n.to_be_bytes());
        k[31] = 1;
        k
    };
    let big: Vec<AllowedIp> = (0..2000u32)
        .map(|n| AllowedIp::v6(Ipv6Addr::from((0xfd00_u128 << 112) | u128::from(n)), 128))
        .collect();
    wg.set_device("wgm0", |mut d| {
        d = d.private_key([7; 32]).replace_peers();
        for n in 0..500u32 {
            let ip = AllowedIp::v4(Ipv4Addr::from(0x0a00_0000 + n), 32);
            d = d.peer(
                WgPeerBuilder::new(key(n))
                    .replace_allowed_ips()
                    .allowed_ip(ip),
            );
        }
        d.peer(
            WgPeerBuilder::new(key(9999))
                .replace_allowed_ips()
                .allowed_ips(big.clone()),
        )
    })
    .await?;

    let device = wg.get_device("wgm0").await?;
    assert_eq!(device.peers.len(), 501);
    let the_big_one = device
        .peers
        .iter()
        .find(|p| p.public_key == key(9999))
        .expect("the peer with 2000 allowed-ips");
    assert_eq!(the_big_one.allowed_ips.len(), 2000);
    Ok(())
}

/// A sub-second keepalive is 1 s in the kernel, as `wg` reads it back. It
/// was truncated to 0, which turns keepalive off, without a word: on a new
/// peer until #529, and on a peer whose keepalive changes until #602.
#[tokio::test]
async fn a_sub_second_keepalive_is_one_second() -> nlink::Result<()> {
    require_root!();
    nlink::require_host_root!();
    nlink::require_modules!("wireguard");

    fn at(keepalive: Duration) -> WireguardConfig {
        WireguardConfig::new().device("wg0", |d| {
            d.listen_port(51824)
                .peer(peer_key(0xc1), |p| p.persistent_keepalive(keepalive))
        })
    }
    fn shows_one_second(ns: &TestNamespace) -> Result<(), String> {
        let shown = ns
            .exec("wg", &["show", "wg0", "persistent-keepalive"])
            .map_err(|e| e.to_string())?;
        // `<public key>\t<seconds or "off">`
        match shown.split_whitespace().nth(1) {
            Some("1") => Ok(()),
            other => Err(format!("wg shows keepalive {other:?}: {shown:?}")),
        }
    }
    let cases = vec![
        case("keepalive-500ms", vec![at(Duration::from_millis(500))]).check(shows_one_second),
        // A live peer's change goes through the update path.
        case(
            "keepalive-25s-to-500ms",
            vec![at(Duration::from_secs(25)), at(Duration::from_millis(500))],
        )
        .check(shows_one_second),
    ];
    assert_converges("wge", cases).await
}

/// #529: an allowed-IP edit asks the kernel, once, whether it removes a
/// single prefix (`WGALLOWEDIP_F_REMOVE_ME`, 6.16+). The probe changes
/// nothing; on a kernel without the flag — this one, 6.12 — it says so and
/// the edit replaces the list, ending where it was declared; with no
/// prefix to remove, only the new one is sent.
#[tokio::test]
async fn an_allowed_ip_edit_probes_for_per_prefix_removal() -> nlink::Result<()> {
    use nlink::netlink::Wireguard;
    require_root!();
    nlink::require_host_root!();
    nlink::require_modules!("wireguard");

    let ns = TestNamespace::new("wg-prefix")?;
    let (route, wg) = (ns.connection()?, ns.connection_for_async::<Wireguard>().await?);
    let net = |n| AllowedIp::v4(Ipv4Addr::new(10, n, 0, 0), 24);
    let config = |nets: Vec<u8>| {
        WireguardConfig::new().device("wg0", move |d| {
            d.listen_port(51830).peer(peer_key(0xd1), move |mut p| {
                for n in &nets {
                    p = p.allowed_ip(net(*n));
                }
                p
            })
        })
    };
    let first = config(vec![0, 1]);
    first.ensure_devices(&route).await?;
    let _ = first.apply(&wg).await?;

    let absent = AllowedIp::v4(Ipv4Addr::new(255, 255, 255, 255), 32);
    let supported = wg.allowed_ip_removal_supported("wg0", peer_key(0xd1), absent).await?;
    let (major, minor) = kernel_version();
    assert_eq!(supported, (major, minor) >= (6, 16), "kernel {major}.{minor}");
    assert_eq!(held_ips(&wg).await?, ["10.0.0.0/24", "10.1.0.0/24"], "the probe changed nothing");

    // 10.1 goes, 10.2 comes.
    let second = config(vec![0, 2]);
    let _ = second.apply(&wg).await?;
    assert_eq!(held_ips(&wg).await?, ["10.0.0.0/24", "10.2.0.0/24"]);
    assert!(second.diff(&wg).await?.is_empty());
    // Only an addition: no list to replace.
    let third = config(vec![0, 2, 3]);
    let diff = third.diff(&wg).await?;
    let (_, changes) = &diff.devices_to_modify[0].1.peers_to_modify[0];
    assert_eq!(changes.allowed_ips_added, [net(3)]);
    assert!(changes.allowed_ips_removed.is_empty());
    let _ = third.apply(&wg).await?;
    assert_eq!(held_ips(&wg).await?, ["10.0.0.0/24", "10.2.0.0/24", "10.3.0.0/24"]);
    Ok(())
}

/// wg0's one peer's allowed IPs, sorted.
async fn held_ips(
    wg: &nlink::netlink::Connection<nlink::netlink::Wireguard>,
) -> nlink::Result<Vec<String>> {
    let mut ips: Vec<String> = wg
        .get_device_by_name("wg0")
        .await?
        .peers
        .remove(0)
        .allowed_ips
        .iter()
        .map(|ip| format!("{}/{}", ip.addr, ip.cidr))
        .collect();
    ips.sort();
    Ok(ips)
}

/// The running kernel's major and minor version.
fn kernel_version() -> (u32, u32) {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let mut parts = release.trim().split(['.', '-']).map(|p| p.parse().unwrap_or(0));
    (parts.next().unwrap_or(0), parts.next().unwrap_or(0))
}

/// #529: a peer whose endpoint is `InitialOnly` keeps the endpoint it
/// roamed to; an enforced one is put back.
#[tokio::test]
async fn an_initial_only_endpoint_lets_a_peer_roam() -> nlink::Result<()> {
    use nlink::netlink::Wireguard;
    use nlink::netlink::genl::wireguard::{EndpointPolicy, WgPeerBuilder};
    require_root!();
    nlink::require_host_root!();
    nlink::require_modules!("wireguard");

    let ns = TestNamespace::new("wg-roam")?;
    let (route, wg) = (ns.connection()?, ns.connection_for_async::<Wireguard>().await?);
    let config = |policy| {
        WireguardConfig::new().device("wg0", move |d| {
            d.listen_port(51831)
                .peer(peer_key(0xd2), move |p| p.endpoint(v4_endpoint()).endpoint_policy(policy))
        })
    };
    let initial_only = config(EndpointPolicy::InitialOnly);
    initial_only.ensure_devices(&route).await?;
    let _ = initial_only.apply(&wg).await?;
    // The peer roams: its handshakes now come from elsewhere.
    let roamed: SocketAddr = "203.0.113.9:40000".parse().unwrap();
    wg.set_peer_by_name("wg0", peer_key(0xd2), |p: WgPeerBuilder| p.endpoint(roamed)).await?;

    assert!(initial_only.diff(&wg).await?.is_empty(), "a roamed peer is left where it went");
    let enforce = config(EndpointPolicy::Enforce).diff(&wg).await?;
    let (_, changes) = &enforce.devices_to_modify[0].1.peers_to_modify[0];
    assert!(changes.endpoint_set, "{enforce}");
    Ok(())
}
