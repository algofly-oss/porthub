//! Persistent sync worker; standalone commands use the same local implementation.
use async_trait::async_trait;
use porthub_components::{
    ipc,
    protocol::sync::{Operation, Options, Progress, Status, Value},
    rpc::{ErrorCode, Failure, Handler, Reply},
};
use porthub_transfer::sync;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

pub struct Worker;
fn status(job: sync::Status) -> Status {
    Status {
        id: job.id,
        source: job.source,
        destination: job.destination,
        state: job.state,
        completed_runs: job.completed_runs,
        last_success_unix: job.last_success_unix,
        message: job.message,
    }
}
fn options(value: Options) -> std::result::Result<sync::Options, Failure> {
    value.validate().map_err(|_| {
        failure(
            ErrorCode::InvalidRequest,
            "Invalid sync source, destination or concurrency",
        )
    })?;
    Ok(sync::Options {
        path: value.path,
        url: value.url,
        connections: value.connections,
        contents_only: value.contents_only,
        force: value.force,
    })
}
fn failure(code: ErrorCode, message: &str) -> Failure {
    Failure {
        code,
        detail: message.into(),
    }
}
#[async_trait]
impl Handler for Worker {
    type Operation = Operation;
    type Value = Value;
    async fn handle(
        &self,
        operation: Operation,
        cancel: CancellationToken,
    ) -> std::result::Result<Reply<Value>, Failure> {
        match operation {
            Operation::List { offset, limit } => {
                if limit == 0 || limit > 32 {
                    return Err(failure(
                        ErrorCode::InvalidRequest,
                        "Sync list limit must be between 1 and 32",
                    ));
                }
                let all = sync::list()
                    .await
                    .map_err(|_| failure(ErrorCode::Unavailable, "Cannot read local sync jobs"))?;
                let total = all.len();
                let mut jobs: Vec<_> = all
                    .into_iter()
                    .skip(offset)
                    .take(limit as usize)
                    .map(status)
                    .collect();
                // Large paths need fewer rows per frame. Core uses the actual
                // returned count to request the next page, without losing jobs.
                while jobs.len() > 1
                    && serde_json::to_vec(&jobs).map_or(true, |bytes| bytes.len() > 48 * 1024)
                {
                    jobs.pop();
                }
                Ok(Reply::Message(Value::Jobs { jobs, total }))
            }
            Operation::Status { id } => {
                let job = sync::status(&id).await.map_err(|_| {
                    failure(
                        ErrorCode::NotFound,
                        "Sync job unavailable; list active jobs first",
                    )
                })?;
                Ok(Reply::Message(Value::Status { job: status(job) }))
            }
            Operation::Stop { id } => {
                sync::stop(&id).await.map_err(|_| {
                    failure(
                        ErrorCode::NotFound,
                        "Sync job unavailable or already stopped",
                    )
                })?;
                Ok(Reply::Message(Value::Stopped))
            }
            Operation::Start {
                options: requested,
                detached,
            } => {
                let requested = options(requested)?;
                if detached {
                    let id = sync::detach(requested).await.map_err(|_| {
                        failure(
                            ErrorCode::Unavailable,
                            "Cannot start detached sync; check source access and receiver URL",
                        )
                    })?;
                    return Ok(Reply::Message(Value::Started { id }));
                }
                let (ready, started) = tokio::sync::oneshot::channel();
                let job_cancel = cancel.child_token();
                let watch_cancel = job_cancel.clone();
                let mut job = tokio::spawn(sync::watch_ready(requested, watch_cancel, Some(ready)));
                let id = match tokio::time::timeout(Duration::from_secs(5), started).await {
                    Ok(Ok(id)) => id,
                    _ => {
                        job_cancel.cancel();
                        let _ = job.await;
                        return Err(failure(
                            ErrorCode::Unavailable,
                            "Cannot start sync watch; check source access and receiver URL",
                        ));
                    }
                };
                let (local, mut remote) = tokio::io::duplex(64 * 1024);
                let identity = id.clone();
                tokio::spawn(async move {
                    let _cleanup = job_cancel.clone().drop_guard();
                    let mut tick = tokio::time::interval(Duration::from_secs(1));
                    loop {
                        tokio::select! { biased;
                            _ = cancel.cancelled() => break,
                            result = &mut job => {
                                let failed = !matches!(result, Ok(Ok(())));
                                let _ = ipc::write(&mut remote, &Progress { job: None, finished: true, failed }, Duration::from_secs(2)).await;
                                return;
                            }
                            _ = remote.read_u8() => break, // EOF/disconnect owns foreground cancellation.
                            _ = tick.tick() => {
                                let progress = Progress { job: sync::status(&identity).await.ok().map(status), finished: false, failed: false };
                                if ipc::write(&mut remote, &progress, Duration::from_secs(2)).await.is_err() { break; }
                            }
                        }
                    }
                    job_cancel.cancel();
                    let _ = job.await;
                });
                Ok(Reply::Stream {
                    value: Value::Started { id },
                    remote: Box::new(local),
                })
            }
        }
    }
}
