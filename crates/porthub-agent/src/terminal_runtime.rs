//! Runtime provisioning belongs to the verified optional terminal component.
use anyhow::{ensure, Result};
use porthub_components::{
    catalog::Component,
    protocol::terminal::{Operation, Value},
};
use std::{path::Path, time::Duration};
pub async fn install(cache: &Path) -> Result<porthub_terminal::runtime::Runtime> {
    let cancel = tokio_util::sync::CancellationToken::new();
    let mut worker = crate::components::worker(Component::Terminal, &cancel).await?;
    let Value::Runtime {
        executable,
        terminfo,
        version,
    } = worker
        .call(
            Operation::Install {
                directory: cache.into(),
            },
            Duration::from_secs(30),
        )
        .await?
    else {
        anyhow::bail!("invalid runtime response")
    };
    ensure!(
        executable.starts_with(cache) && terminfo.starts_with(cache),
        "terminal component returned an unrelated runtime directory"
    );
    Ok(porthub_terminal::runtime::Runtime {
        executable,
        terminfo,
        version,
    })
}
