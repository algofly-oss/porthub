use anyhow::Result;
use porthub_firewall::{
    kernel::{rules, Kernel},
    Policy,
};
use std::{collections::BTreeMap, time::Duration};
// nftables transaction generations are namespace-wide, including foreign tables.
static KERNEL_TEST_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[test]
fn planner_rejects_foreign_tables_and_invalid_policies() {
    let mut policies = BTreeMap::new();
    policies.insert(
        8080,
        Policy {
            is_public: true,
            allowed_ips: vec![],
        },
    );
    assert!(rules(&policies, "filter", Duration::from_secs(300)).is_err());
    assert!(rules(&policies, "porthub", Duration::ZERO).is_err());
    policies
        .get_mut(&8080)
        .unwrap()
        .allowed_ips
        .push("127.0.0.1".parse().unwrap());
    assert!(rules(&policies, "porthub", Duration::from_secs(300)).is_err());
}

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN in a disposable network namespace"]
async fn native_netlink_enforces_policy_counts_bytes_and_preserves_other_tables() -> Result<()> {
    if std::env::var("PORTHUB_FIREWALL_KERNEL_TEST").as_deref() != Ok("1") {
        eprintln!("kernel test requires the dedicated isolated-container command");
        return Ok(());
    }
    let _isolation = KERNEL_TEST_SERIAL.lock().await;
    use nlink::netlink::{nftables::Family, Connection, Nftables};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    let connection = Connection::<Nftables>::new()?;
    connection
        .add_table("foreign_fixture", Family::Inet)
        .await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await?;
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
        #[allow(unreachable_code)]
        Ok::<_, std::io::Error>(())
    });
    let kernel = Kernel::new("porthub_test", Duration::from_secs(300))?;
    let mut policies = BTreeMap::new();
    policies.insert(
        address.port(),
        Policy {
            is_public: false,
            allowed_ips: vec!["127.0.0.1".parse()?],
        },
    );
    assert!(kernel.apply(&policies).await? > 0);
    let mut client = TcpStream::connect(address).await?;
    client.write_all(b"native netlink echo").await?;
    let mut answer = [0; 19];
    client.read_exact(&mut answer).await?;
    assert_eq!(&answer, b"native netlink echo");
    let counter_name = format!("cnt_in_{}", address.port());
    let first = kernel.counters().await?;
    assert!(first[&counter_name] > 0);
    assert_eq!(
        kernel.apply(&policies).await?,
        0,
        "unchanged policies should be a no-op"
    );
    assert!(
        kernel.counters().await?[&counter_name] >= first[&counter_name],
        "reload reset counters"
    );
    assert!(kernel
        .recent(address.port(), "in", Duration::from_secs(3))
        .await?
        .contains(&"127.0.0.1".to_owned()));
    drop(client);
    policies.get_mut(&address.port()).unwrap().allowed_ips = vec!["192.0.2.42".parse()?];
    kernel.apply(&policies).await?;
    assert!(
        tokio::time::timeout(Duration::from_millis(250), TcpStream::connect(address))
            .await
            .is_err(),
        "non-allowed source reached listener"
    );
    assert!(kernel.counters().await?[&format!("cnt_drop_{}", address.port())] > 0);
    kernel.apply(&BTreeMap::new()).await?;
    let _ = TcpStream::connect(address).await?;
    assert!(
        connection
            .list_tables()
            .await?
            .iter()
            .any(|t| t.name == "foreign_fixture"),
        "changed an unrelated table"
    );
    connection.del_table("porthub_test", Family::Inet).await?;
    connection
        .del_table("foreign_fixture", Family::Inet)
        .await?;
    server.abort();
    Ok(())
}

/// Every operation is confined to a throwaway Docker network namespace. In
/// particular, a full telemetry set must never become an authorization failure.
#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN in a disposable network namespace"]
async fn accepted_packet_sources_refresh_filter_and_never_control_verdicts() -> Result<()> {
    if std::env::var("PORTHUB_FIREWALL_KERNEL_TEST").as_deref() != Ok("1") {
        return Ok(());
    }
    let _isolation = KERNEL_TEST_SERIAL.lock().await;
    use nlink::netlink::{
        nftables::{Family, Set, SetElement, SetKeyType},
        Connection, Nftables,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpSocket, TcpStream},
    };
    async fn echo(listener: TcpListener) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = stream.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        })
    }
    async fn exchange(stream: &mut TcpStream) -> Result<()> {
        stream.write_all(b"observed-packet").await?;
        let mut bytes = [0; 15];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut bytes)).await??;
        assert_eq!(&bytes, b"observed-packet");
        Ok(())
    }
    let connection = Connection::<Nftables>::new()?;
    connection
        .add_table("foreign_accepted_fixture", Family::Inet)
        .await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = echo(listener).await;
    let other = TcpListener::bind("127.0.0.1:0").await?;
    let other_address = other.local_addr()?;
    let kernel = Kernel::new("porthub_accepted_test", Duration::from_secs(3))?;
    let mut policies = BTreeMap::from([
        (
            address.port(),
            Policy {
                is_public: false,
                allowed_ips: vec!["127.0.0.1".parse()?],
            },
        ),
        (
            other_address.port(),
            Policy {
                is_public: true,
                allowed_ips: vec![],
            },
        ),
    ]);
    kernel.apply(&policies).await?;
    let mut client = TcpStream::connect(address).await?;
    exchange(&mut client).await?;
    assert_eq!(
        kernel
            .accepted_recent(address.port(), Duration::from_secs(1))
            .await?,
        vec!["127.0.0.1"]
    );
    assert!(
        kernel
            .accepted_recent(other_address.port(), Duration::from_secs(1))
            .await?
            .is_empty(),
        "source leaked between owned ports"
    );
    // This is one established connection, older than the entire set retention.
    // NEW-only tracking expires, while every-packet accepted tracking survives.
    for _ in 0..8 {
        tokio::time::sleep(Duration::from_millis(450)).await;
        exchange(&mut client).await?;
    }
    assert!(
        kernel
            .recent(address.port(), "in", Duration::from_secs(3))
            .await?
            .is_empty(),
        "legacy NEW attempts unexpectedly refreshed"
    );
    assert_eq!(
        kernel
            .accepted_recent(address.port(), Duration::from_millis(500))
            .await?,
        vec!["127.0.0.1"]
    );
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(
        kernel
            .accepted_recent(address.port(), Duration::from_secs(1))
            .await?
            .is_empty(),
        "retained source falsely attributed to a narrower observation window"
    );
    let socket = TcpSocket::new_v4()?;
    socket.bind("127.0.0.2:0".parse()?)?;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), socket.connect(address))
            .await
            .is_err()
    );
    assert!(
        kernel
            .recent(address.port(), "in", Duration::from_secs(3))
            .await?
            .contains(&"127.0.0.2".into()),
        "legacy attempt tracking was lost"
    );
    assert!(
        !kernel
            .accepted_recent(address.port(), Duration::from_secs(3))
            .await?
            .contains(&"127.0.0.2".into()),
        "blocked source reported as accepted"
    );
    drop(client);
    // A second independently owned table exercises full-set failures without
    // changing the original restrictive table or any unrelated table.
    let full = Kernel::new("porthub_accepted_full", Duration::from_secs(30))?;
    full.apply(&BTreeMap::from([(
        address.port(),
        Policy {
            is_public: true,
            allowed_ips: vec![],
        },
    )]))
    .await?;
    let set = Set::new(
        "porthub_accepted_full",
        &format!("accepted_{}", address.port()),
    )
    .key_type(SetKeyType::Ipv4Addr)
    .dynamic()
    .size(4096)
    .timeout(Duration::from_secs(30));
    let elements: Vec<_> = (0..4096u32)
        .map(|i| {
            SetElement::ipv4(std::net::Ipv4Addr::from(0xc6120000 + i))
                .with_timeout(Duration::from_secs(30))
        })
        .collect();
    for chunk in elements.chunks(256) {
        connection.add_set_elements(&set, chunk).await?;
    }
    assert_eq!(
        connection
            .list_set_elements(
                "porthub_accepted_full",
                &format!("accepted_{}", address.port()),
                Family::Inet
            )
            .await?
            .len(),
        4096
    );
    let mut allowed = TcpStream::connect(address).await?;
    exchange(&mut allowed).await?;
    assert!(
        full.counters().await?[&format!("cnt_in_{}", address.port())] > 0,
        "full observation set changed allow/counter semantics"
    );
    assert!(
        !full
            .accepted_recent(address.port(), Duration::from_secs(30))
            .await?
            .contains(&"127.0.0.1".into()),
        "fixture did not exercise full-set insertion failure"
    );
    // Public IPv6 traffic is included, with its true address family.
    connection
        .del_table("porthub_accepted_full", Family::Inet)
        .await?;
    let listener6 = TcpListener::bind("[::1]:0").await?;
    let address6 = listener6.local_addr()?;
    let server6 = echo(listener6).await;
    policies.insert(
        address6.port(),
        Policy {
            is_public: true,
            allowed_ips: vec![],
        },
    );
    kernel.apply(&policies).await?;
    let mut client6 = TcpStream::connect(address6).await?;
    exchange(&mut client6).await?;
    assert_eq!(
        kernel
            .accepted_recent(address6.port(), Duration::from_secs(1))
            .await?,
        vec!["::1"]
    );
    assert!(connection
        .list_tables()
        .await?
        .iter()
        .any(|t| t.name == "foreign_accepted_fixture"));
    connection
        .del_table("porthub_accepted_test", Family::Inet)
        .await?;
    connection
        .del_table("foreign_accepted_fixture", Family::Inet)
        .await?;
    server.abort();
    server6.abort();
    Ok(())
}
