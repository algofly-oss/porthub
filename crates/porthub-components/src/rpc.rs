//! Persistent typed worker RPC and explicit stream upgrades. Machine credentials
//! are not part of this protocol; sharing capabilities belong to tool contracts.
use crate::{
    catalog::Artifact,
    ipc::{self, Hello, Request, Response},
    local::{Endpoint, Listener, Stream},
};
use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio_util::sync::CancellationToken;
const IDLE: Duration = Duration::from_secs(60);
const MAX_CALL: Duration = Duration::from_secs(300);
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    Unavailable,
    Denied,
    NotFound,
    Internal,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Failure {
    pub code: ErrorCode,
    pub detail: String,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Outcome<T> {
    Ok { value: T, stream: bool },
    Error { failure: Failure },
}

pub enum Reply<T> {
    Message(T),
    Stream { value: T, remote: Stream },
}
#[async_trait]
pub trait Handler: Send + Sync + 'static {
    type Operation: DeserializeOwned + Send;
    type Value: Serialize + Send + Sync;
    async fn handle(
        &self,
        operation: Self::Operation,
        cancel: CancellationToken,
    ) -> std::result::Result<Reply<Self::Value>, Failure>;
}

pub struct Client {
    stream: Stream,
    next: u64,
    poisoned: bool,
}
impl Client {
    pub async fn connect(endpoint: &Endpoint, artifact: &Artifact) -> Result<Self> {
        let mut stream = tokio::time::timeout(Duration::from_secs(5), endpoint.connect()).await??;
        let hello: Hello = ipc::read(&mut stream, Duration::from_secs(5)).await?;
        hello.validate(artifact.component, &artifact.version)?;
        ipc::write(&mut stream, &hello, Duration::from_secs(5)).await?;
        Ok(Self {
            stream,
            next: 0,
            poisoned: false,
        })
    }
    async fn exchange<T: Serialize, R: DeserializeOwned>(
        &mut self,
        operation: T,
        timeout: Duration,
        want_stream: bool,
    ) -> Result<R> {
        ensure!(
            !self.poisoned,
            "component connection requires reconnecting after an interrupted request"
        );
        ensure!(
            !timeout.is_zero() && timeout <= MAX_CALL,
            "invalid component request timeout"
        );
        self.next = self
            .next
            .checked_add(1)
            .context("component request ID exhausted")?;
        let request = Request {
            id: self.next,
            deadline_unix_ms: now_ms().saturating_add(timeout.as_millis() as u64),
            operation,
        };
        // Dropping this future mid-frame leaves the connection unusable. Never
        // pair a later request with the interrupted request's response.
        self.poisoned = true;
        let response: Response<Outcome<R>> = tokio::time::timeout(timeout, async {
            ipc::write(&mut self.stream, &request, timeout).await?;
            ipc::read(&mut self.stream, timeout).await
        })
        .await??;
        ensure!(response.id == self.next, "component response ID mismatch");
        match response.result {
            Outcome::Ok { value, stream } => {
                ensure!(stream == want_stream, "unexpected component stream upgrade");
                self.poisoned = false;
                Ok(value)
            }
            Outcome::Error { failure } => {
                ensure!(
                    failure.detail.len() <= 512 && !failure.detail.chars().any(char::is_control),
                    "invalid component error"
                );
                self.poisoned = false;
                anyhow::bail!("{}", failure.detail)
            }
        }
    }
    pub async fn call<T: Serialize, R: DeserializeOwned>(
        &mut self,
        operation: T,
        timeout: Duration,
    ) -> Result<R> {
        self.exchange(operation, timeout, false).await
    }
    pub async fn upgrade<T: Serialize, R: DeserializeOwned>(
        mut self,
        operation: T,
        timeout: Duration,
    ) -> Result<(R, Stream)> {
        let value = self.exchange(operation, timeout, true).await?;
        Ok((value, self.stream))
    }
}
async fn connection<H: Handler>(
    mut stream: Stream,
    handler: Arc<H>,
    hello: Hello,
    cancel: CancellationToken,
) -> Result<()> {
    ipc::write(&mut stream, &hello, Duration::from_secs(5)).await?;
    let peer: Hello = ipc::read(&mut stream, Duration::from_secs(5)).await?;
    peer.validate(hello.component, &hello.version)?;
    let mut previous = 0;
    loop {
        let request: Request<H::Operation> = tokio::select! { biased;
            _ = cancel.cancelled() => return Ok(()),
            result = ipc::read(&mut stream, IDLE) => result?,
        };
        let remaining = request.deadline_unix_ms.saturating_sub(now_ms());
        ensure!(
            request.id > previous && remaining > 0 && remaining <= MAX_CALL.as_millis() as u64,
            "invalid component request ID or deadline"
        );
        previous = request.id;
        let operation_cancel = cancel.child_token();
        let _operation_guard = operation_cancel.clone().drop_guard();
        let result = tokio::select! { biased;
            _ = cancel.cancelled() => { operation_cancel.cancel(); return Ok(()); },
            result = tokio::time::timeout(Duration::from_millis(remaining), handler.handle(request.operation, operation_cancel.clone())) => result,
        };
        let reply = match result {
            Ok(Ok(reply)) => reply,
            result => {
                let failure = match result {
                    Ok(Err(failure)) => failure,
                    Err(_) => Failure {
                        code: ErrorCode::Unavailable,
                        detail: "Component operation timed out".into(),
                    },
                    _ => unreachable!(),
                };
                ensure!(
                    failure.detail.len() <= 512 && !failure.detail.chars().any(char::is_control),
                    "invalid component failure"
                );
                ipc::write(
                    &mut stream,
                    &Response::<Outcome<H::Value>> {
                        id: request.id,
                        result: Outcome::Error { failure },
                    },
                    Duration::from_secs(5),
                )
                .await?;
                continue;
            }
        };
        let (value, remote) = match reply {
            Reply::Message(value) => (value, None),
            Reply::Stream { value, remote } => (value, Some(remote)),
        };
        ipc::write(
            &mut stream,
            &Response {
                id: request.id,
                result: Outcome::Ok {
                    value,
                    stream: remote.is_some(),
                },
            },
            Duration::from_secs(5),
        )
        .await?;
        if let Some(mut remote) = remote {
            // Existing streams remain with this worker across component updates.
            tokio::select! { biased; _ = cancel.cancelled() => {}, _ = tokio::io::copy_bidirectional(&mut stream, &mut remote) => {} }
            return Ok(());
        }
    }
}
/// One process serves many calls and streams; no per-operation subprocesses.
/// Idle workers exit after five minutes; active stream tasks prevent idle exit.
pub async fn serve<H: Handler>(
    endpoint: Endpoint,
    hello: Hello,
    handler: Arc<H>,
    cancel: CancellationToken,
) -> Result<()> {
    let mut listener = Listener::bind(endpoint).await?;
    let mut clients = tokio::task::JoinSet::new();
    let mut tick = tokio::time::interval(IDLE);
    tick.tick().await;
    let mut idle = 0;
    loop {
        tokio::select! { biased;
            _ = cancel.cancelled() => break,
            _ = tick.tick() => {
                if clients.is_empty() { idle += 1; } else { idle = 0; }
                if idle >= 5 { break; }
            },
            _ = clients.join_next(), if !clients.is_empty() => {},
            result = listener.accept(), if clients.len() < 32 => {
                // Rejected peers and closed startup probes do not stop other clients.
                match result {
                    Ok(stream) => {
                        idle = 0;
                        let handler = handler.clone(); let hello = hello.clone(); let child = cancel.child_token();
                        clients.spawn(async move { let _ = connection(stream, handler, hello, child).await; });
                    }
                    Err(_) => { tokio::select! { _ = cancel.cancelled() => break, _ = tokio::time::sleep(Duration::from_millis(100)) => {} } }
                }
            },
        }
    }
    clients.shutdown().await;
    Ok(())
}
