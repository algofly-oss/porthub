//! Recompute optimistic nftables changes when another writer commits first.
use nlink::netlink::{nftables::config::NftablesConfig, Connection, Nftables, Result};
use std::{future::Future, time::Duration};

async fn retry<T, F, Fut>(mut operation: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    for attempt in 0..5 {
        match operation().await {
            Err(error) if error.errno() == Some(libc::ERESTART) && attempt < 4 => {
                // The entire stale batch was refused. Re-read the ruleset;
                // replaying the old diff could target somebody else's rules.
                tokio::time::sleep(Duration::from_millis(10 * (attempt + 1))).await;
            }
            result => return result,
        }
    }
    unreachable!()
}

pub(super) async fn apply(config: &NftablesConfig, connection: &Connection<Nftables>) -> Result<()> {
    retry(|| async { config.diff(connection).await?.apply(connection).await }).await.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nlink::netlink::{nftables::Family, Error};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn conflicts_are_bounded_and_permission_failures_are_not_retried() {
        for (errno, expected) in [(libc::ERESTART, 5), (libc::EPERM, 1)] {
            let calls = AtomicUsize::new(0);
            let result: Result<()> = retry(|| async {
                calls.fetch_add(1, Ordering::Relaxed);
                Err(Error::from_errno(errno))
            }).await;
            assert_eq!(result.unwrap_err().errno(), Some(errno));
            assert_eq!(calls.load(Ordering::Relaxed), expected);
        }
    }

    #[tokio::test]
    #[ignore = "requires an explicitly owned disposable container network namespace"]
    async fn stale_kernel_generation_is_recomputed_without_removing_foreign_rules() -> anyhow::Result<()> {
        anyhow::ensure!(std::env::var("PORTHUB_TEST_OWNED_NETNS").as_deref() == Ok("1")
            && std::path::Path::new("/.dockerenv").is_file(), "owned test namespace required");
        let connection = Connection::<Nftables>::new()?;
        let foreign = Connection::<Nftables>::new()?;
        let config = NftablesConfig::new().table("porthub_retry_test", Family::Ip, |table| table);
        let calls = AtomicUsize::new(0);
        retry(|| async {
            let diff = config.diff(&connection).await?;
            if calls.fetch_add(1, Ordering::Relaxed) == 0 {
                foreign.add_table("foreign_retry_test", Family::Ip).await?;
            }
            diff.apply(&connection).await
        }).await?;
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        let tables = connection.list_tables().await?;
        assert!(tables.iter().any(|table| table.name == "porthub_retry_test"));
        assert!(tables.iter().any(|table| table.name == "foreign_retry_test"));
        connection.del_table("porthub_retry_test", Family::Ip).await?;
        foreign.del_table("foreign_retry_test", Family::Ip).await?;
        Ok(())
    }
}
