//! CLI formatting stays in core; all watch work travels over typed local IPC.
use anyhow::{ensure, Result};
use porthub_components::{
    catalog::Component,
    ipc,
    protocol::sync::{Operation, Options, Progress, Status, Value},
};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
const CALL: Duration = Duration::from_secs(15);
pub async fn watch(mut options: Options, detached: bool, cancel: CancellationToken) -> Result<()> {
    options.path = options.path.canonicalize()?;
    ensure!(options.path.is_dir(), "--watch requires a directory");
    options.validate()?;
    let mut client = crate::components::worker(Component::Sync, &cancel).await?;
    if detached {
        let reply: Value = client
            .call(
                Operation::Start {
                    options,
                    detached: true,
                },
                CALL,
            )
            .await?;
        let Value::Started { id } = reply else {
            anyhow::bail!("unexpected sync worker response")
        };
        println!("Sync started in background: {id}\nView: porthub sync status {id}\nStop: porthub sync stop {id}");
        return Ok(());
    }
    let (reply, mut stream) = client
        .upgrade::<_, Value>(
            Operation::Start {
                options,
                detached: false,
            },
            CALL,
        )
        .await?;
    let Value::Started { id } = reply else {
        anyhow::bail!("unexpected sync worker response")
    };
    eprintln!("Watching (job {id}); Ctrl-C or porthub sync stop {id} to stop");
    let mut last = None;
    loop {
        let progress: Progress = tokio::select! { biased; _ = cancel.cancelled() => return Ok(()),
            result = ipc::read(&mut stream, Duration::from_secs(15)) => result?,
        };
        if let Some(job) = progress.job {
            let current = (job.completed_runs, job.message.clone());
            if last.as_ref() != Some(&current) {
                eprintln!("{}", job.message);
                last = Some(current);
            }
        }
        if progress.finished {
            ensure!(
                !progress.failed,
                "sync watch failed; inspect source access and receiver connectivity"
            );
            return Ok(());
        }
    }
}
pub async fn list(cancel: &CancellationToken) -> Result<Vec<Status>> {
    let mut client = crate::components::worker(Component::Sync, cancel).await?;
    let mut all = Vec::new();
    loop {
        let reply: Value = client
            .call(
                Operation::List {
                    offset: all.len(),
                    limit: 32,
                },
                CALL,
            )
            .await?;
        let Value::Jobs { jobs, total } = reply else {
            anyhow::bail!("unexpected sync worker response")
        };
        ensure!(
            total <= 4096 && (!jobs.is_empty() || all.len() >= total),
            "invalid sync job page"
        );
        all.extend(jobs);
        if all.len() >= total {
            return Ok(all);
        }
    }
}
pub async fn status(id: String, cancel: &CancellationToken) -> Result<Status> {
    let mut client = crate::components::worker(Component::Sync, cancel).await?;
    let reply: Value = client.call(Operation::Status { id }, CALL).await?;
    let Value::Status { job } = reply else {
        anyhow::bail!("unexpected sync worker response")
    };
    Ok(job)
}
pub async fn stop(id: String, cancel: &CancellationToken) -> Result<()> {
    let mut client = crate::components::worker(Component::Sync, cancel).await?;
    let reply: Value = client.call(Operation::Stop { id }, CALL).await?;
    ensure!(
        matches!(reply, Value::Stopped),
        "unexpected sync worker response"
    );
    Ok(())
}
