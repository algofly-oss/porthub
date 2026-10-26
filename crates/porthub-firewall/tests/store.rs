use anyhow::Result;
use porthub_firewall::{store::Store, Policy, Sample};
use std::time::{SystemTime, UNIX_EPOCH};
#[tokio::test]
async fn migrates_legacy_sqlite_and_preserves_policies_and_traffic() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("firewall.db");
    {
        let legacy = tokio_rusqlite::rusqlite::Connection::open(&path)?;
        legacy.execute_batch("CREATE TABLE allowlists(port INTEGER PRIMARY KEY,ips TEXT); INSERT INTO allowlists VALUES(8080,'[\"127.0.0.1\"]'); CREATE TABLE traffic_buffer(port INTEGER NOT NULL,ts INTEGER NOT NULL,in_bytes INTEGER NOT NULL,out_bytes INTEGER NOT NULL);")?;
    }
    let store = Store::open(&path).await?;
    assert_eq!(
        store.policies().await?[&8080],
        Policy {
            is_public: false,
            allowed_ips: vec!["127.0.0.1".parse()?]
        }
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let sample = Sample {
        timestamp: now,
        interval_seconds: 1.25,
        in_bytes: 42,
        out_bytes: 84,
        drop_bytes: 7,
        incoming_ips: vec!["127.0.0.1".into()],
        outgoing_ips: vec!["127.0.0.2".into()],
        blocked_ips: vec!["192.0.2.1".into()],
    };
    store.record(vec![(8080, sample)]).await?;
    assert!(store.snapshot(vec![8081]).await?.is_empty());
    let snapshot = store.snapshot(vec![8080]).await?;
    assert_eq!(snapshot[&8080][0].in_bytes, 42);
    assert_eq!(snapshot[&8080][0].interval_seconds, 1.25);
    assert_eq!(store.active().await?[0]["port"], 8080);
    assert_eq!(store.hits(8080, 10).await?[0]["ip"], "127.0.0.1");
    store
        .policy(
            8081,
            Some(Policy {
                is_public: true,
                allowed_ips: vec![],
            }),
        )
        .await?;
    store.policy(8080, None).await?;
    let reopened = Store::open(&path).await?;
    assert!(!reopened.policies().await?.contains_key(&8080));
    assert!(reopened.policies().await?[&8081].is_public);
    assert_eq!(reopened.snapshot(vec![]).await?[&8080][0].out_bytes, 84);
    Ok(())
}

#[tokio::test]
async fn retiring_a_port_removes_its_history_without_affecting_other_ports() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let store = Store::open(&directory.path().join("firewall.db")).await?;
    let sample = Sample {
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64,
        interval_seconds: 1.,
        in_bytes: 20,
        out_bytes: 40,
        drop_bytes: 0,
        incoming_ips: vec!["192.0.2.1".into()],
        outgoing_ips: vec![],
        blocked_ips: vec![],
    };
    store
        .record(vec![(8000, sample.clone()), (8001, sample)])
        .await?;
    store.purge(8000).await?;
    assert!(store.snapshot(vec![8000]).await?.is_empty());
    assert!(store.hits(8000, 10).await?.is_empty());
    assert_eq!(store.active().await?.len(), 1);
    assert_eq!(store.snapshot(vec![8001]).await?[&8001][0].in_bytes, 20);
    store.purge(8000).await?;
    Ok(())
}
