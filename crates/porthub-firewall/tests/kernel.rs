use anyhow::Result;
use porthub_firewall::{
    kernel::{rules, Kernel},
    Policy,
};
use std::{collections::BTreeMap, time::Duration};

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
