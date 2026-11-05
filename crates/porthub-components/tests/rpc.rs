use anyhow::Result;
use async_trait::async_trait;
use porthub_components::{
    catalog::{Artifact, Blob, Component, PROTOCOL, TARGETS},
    ipc::{self, Hello, Request},
    local::Endpoint,
    rpc::{self, Client, Failure, Handler, Reply},
};
use serde::{Deserialize, Serialize};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
#[derive(Serialize, Deserialize)]
enum Operation {
    Echo(String),
    Stream,
    Wait,
}
#[derive(Serialize, Deserialize)]
struct Value {
    text: String,
    count: usize,
}
struct Echo {
    count: AtomicUsize,
}
#[async_trait]
impl Handler for Echo {
    type Operation = Operation;
    type Value = Value;
    async fn handle(
        &self,
        operation: Operation,
        cancel: CancellationToken,
    ) -> std::result::Result<Reply<Value>, Failure> {
        let count = self.count.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(match operation {
            Operation::Echo(text) => Reply::Message(Value { text, count }),
            Operation::Stream => {
                let (local, mut remote) = tokio::io::duplex(1024);
                tokio::spawn(async move {
                    let (mut reader, mut writer) = tokio::io::split(&mut remote);
                    tokio::select! { _ = cancel.cancelled() => {}, _ = tokio::io::copy(&mut reader, &mut writer) => {} }
                });
                Reply::Stream {
                    value: Value {
                        text: "stream".into(),
                        count,
                    },
                    remote: Box::new(local),
                }
            }
            Operation::Wait => std::future::pending().await,
        })
    }
}
fn artifact() -> Artifact {
    Artifact {
        component: Component::Sync,
        version: "0.1.0".parse().unwrap(),
        target: TARGETS[0].into(),
        core: ">=1.10.0".parse().unwrap(),
        protocols: vec![PROTOCOL],
        source_revision: "a".repeat(40),
        build_inputs: "b".repeat(64),
        executable: Blob {
            size: 1,
            sha256: "c".repeat(64),
        },
        release: "1.11.0".parse().unwrap(),
        archive: Blob {
            size: 1,
            sha256: "d".repeat(64),
        },
    }
}
async fn client(endpoint: &Endpoint, artifact: &Artifact) -> Client {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(client) = Client::connect(endpoint, artifact).await {
                return client;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}
#[tokio::test]
async fn persistent_rpc_stream_upgrade_and_interrupted_request_recovery() -> Result<()> {
    let root = tempfile::tempdir()?;
    let artifact = artifact();
    let endpoint = Endpoint::for_artifact(root.path(), &artifact)?;
    let cancel = CancellationToken::new();
    let hello = Hello {
        component: artifact.component,
        protocol: PROTOCOL,
        version: artifact.version.clone(),
    };
    let handler = Arc::new(Echo {
        count: AtomicUsize::new(0),
    });
    let server = tokio::spawn(rpc::serve(
        endpoint.clone(),
        hello.clone(),
        handler.clone(),
        cancel.clone(),
    ));
    let mut connection = client(&endpoint, &artifact).await;
    for (count, text) in [(1, "first"), (2, "second"), (3, "third")] {
        let response: Value = connection
            .call(Operation::Echo(text.into()), Duration::from_secs(1))
            .await?;
        assert_eq!(response.text, text);
        assert_eq!(response.count, count);
    }
    let streaming = client(&endpoint, &artifact).await;
    let (_, mut stream) = streaming
        .upgrade::<_, Value>(Operation::Stream, Duration::from_secs(1))
        .await?;
    stream.write_all(b"persistent stream").await?;
    let mut bytes = [0; 17];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut bytes)).await??;
    assert_eq!(&bytes, b"persistent stream");
    // Existing streams remain usable while other requests/connections operate.
    let mut interrupted = client(&endpoint, &artifact).await;
    {
        // Cancel a live request deterministically. A server deadline response is
        // a complete frame and may legitimately leave the connection reusable.
        let call = interrupted.call::<_, Value>(Operation::Wait, Duration::from_secs(1));
        tokio::pin!(call);
        tokio::select! { biased;
            result = &mut call => panic!("pending operation unexpectedly completed: {}", result.is_ok()),
            _ = tokio::time::sleep(Duration::from_millis(20)) => {},
        }
    }
    assert!(interrupted
        .call::<_, Value>(
            Operation::Echo("must reconnect".into()),
            Duration::from_secs(1)
        )
        .await
        .is_err());
    let mut replacement = client(&endpoint, &artifact).await;
    let value: Value = replacement
        .call(Operation::Echo("recovered".into()), Duration::from_secs(1))
        .await?;
    assert_eq!(value.text, "recovered");
    stream.write_all(b"still alive").await?;
    let mut bytes = [0; 11];
    stream.read_exact(&mut bytes).await?;
    assert_eq!(&bytes, b"still alive");
    // Deadlines are validated before the handler sees an operation.
    let before = handler.count.load(Ordering::SeqCst);
    let mut malformed = endpoint.connect().await?;
    let _: Hello = ipc::read(&mut malformed, Duration::from_secs(1)).await?;
    ipc::write(&mut malformed, &hello, Duration::from_secs(1)).await?;
    ipc::write(
        &mut malformed,
        &Request {
            id: 1,
            deadline_unix_ms: u64::MAX,
            operation: Operation::Echo("invalid".into()),
        },
        Duration::from_secs(1),
    )
    .await?;
    assert!(
        ipc::read::<serde_json::Value>(&mut malformed, Duration::from_secs(1))
            .await
            .is_err()
    );
    assert_eq!(handler.count.load(Ordering::SeqCst), before);
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), server).await???;
    Ok(())
}
