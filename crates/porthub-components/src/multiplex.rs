//! Concurrent RPC and upgraded streams over one private inherited pipe pair.
//! HTTP/2 supplies bounded per-stream flow control; no network listener is used.
use crate::{
    ipc::Hello,
    local::Stream,
    rpc::{self, Handler},
};
use anyhow::{ensure, Context, Result};
use bytes::{Buf, Bytes};
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;
const WINDOW: u32 = 65536;
const LIMIT: u32 = 128;
const PATH: &str = "/porthub/component/v1";
fn io_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

struct Channel {
    receive: h2::RecvStream,
    send: h2::SendStream<Bytes>,
    pending: Bytes,
    ended: bool,
    _owner: Option<Arc<Carrier>>,
}
impl AsyncRead for Channel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.pending.is_empty() {
                let count = output.remaining().min(self.pending.len());
                output.put_slice(&self.pending[..count]);
                self.pending.advance(count);
                self.receive
                    .flow_control()
                    .release_capacity(count)
                    .map_err(io_error)?;
                return Poll::Ready(Ok(()));
            }
            match self.receive.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(io_error(error))),
                Poll::Ready(Some(Ok(bytes))) => self.pending = bytes,
            }
        }
    }
}
impl AsyncWrite for Channel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.ended {
            return Poll::Ready(Err(io_error("component pipe is closed")));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let count = bytes.len().min(16384);
        self.send.reserve_capacity(count);
        let available = match self.send.poll_capacity(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Some(Ok(available))) => available,
            Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(io_error(error))),
            Poll::Ready(None) => return Poll::Ready(Err(io_error("component pipe is closed"))),
        };
        let count = count.min(available);
        if count == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.send
            .send_data(Bytes::copy_from_slice(&bytes[..count]), false)
            .map_err(io_error)?;
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        if !self.ended {
            self.send.send_data(Bytes::new(), true).map_err(io_error)?;
            self.ended = true;
        }
        Poll::Ready(Ok(()))
    }
}
impl Drop for Channel {
    fn drop(&mut self) {
        // Cancel abandoned streams. A graceful half-close must preserve DATA
        // already queued for delivery to the peer.
        if !self.ended {
            self.send.send_reset(h2::Reason::CANCEL);
        }
    }
}

pub struct Carrier {
    sender: Mutex<h2::client::SendRequest<Bytes>>,
    driver: tokio::task::AbortHandle,
}
impl Drop for Carrier {
    fn drop(&mut self) {
        self.driver.abort();
    }
}
impl Carrier {
    pub fn is_closed(&self) -> bool {
        self.driver.is_finished()
    }
    /// The transport is owned by the connection driver. For a subprocess pipe,
    /// its kill-on-drop guard therefore survives as long as any channel does.
    pub async fn connect<T>(transport: T) -> Result<Arc<Self>>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (sender, connection) = tokio::time::timeout(
            Duration::from_secs(5),
            h2::client::Builder::new()
                .initial_window_size(WINDOW)
                .initial_connection_window_size(WINDOW * (LIMIT + 1))
                .max_send_buffer_size(WINDOW as usize)
                .max_header_list_size(16384)
                .handshake(transport),
        )
        .await??;
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Arc::new(Self {
            sender: Mutex::new(sender),
            driver: driver.abort_handle(),
        }))
    }
    pub async fn open(self: &Arc<Self>) -> Result<Stream> {
        tokio::time::timeout(Duration::from_secs(5), async {
            let sender = self.sender.lock().unwrap().clone();
            let mut sender = sender.ready().await?;
            let request = http::Request::builder()
                .method("POST")
                .uri(format!("http://porthub.internal{PATH}"))
                .body(())?;
            let (response, send) = sender.send_request(request, false)?;
            let response = response.await?;
            ensure!(
                response.status() == http::StatusCode::OK,
                "component pipe admission failed"
            );
            Ok::<Stream, anyhow::Error>(Box::new(Channel {
                receive: response.into_body(),
                send,
                pending: Bytes::new(),
                ended: false,
                _owner: Some(self.clone()),
            }))
        })
        .await
        .context("component pipe admission timed out")?
    }
}

pub async fn serve<T, H>(
    transport: T,
    hello: Hello,
    handler: Arc<H>,
    cancel: CancellationToken,
) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
    H: Handler,
{
    let mut connection = h2::server::Builder::new()
        .initial_window_size(WINDOW)
        .initial_connection_window_size(WINDOW * (LIMIT + 1))
        .max_send_buffer_size(WINDOW as usize)
        .max_header_list_size(16384)
        .max_concurrent_streams(LIMIT.min(handler.connection_limit() as u32))
        .handshake(transport)
        .await?;
    let mut clients = tokio::task::JoinSet::new();
    let _cancel = cancel.clone().drop_guard();
    loop {
        tokio::select! { biased;
            _=cancel.cancelled()=>break,
            _=clients.join_next(), if !clients.is_empty()=>{},
            incoming=connection.accept()=>{
                let Some(incoming)=incoming else { break; };
                let (request,mut respond)=incoming?;
                if request.method()!=http::Method::POST || request.uri().path()!=PATH || clients.len()>=handler.connection_limit().min(LIMIT as usize) {
                    respond.send_reset(h2::Reason::REFUSED_STREAM); continue;
                }
                let send=respond.send_response(http::Response::builder().status(200).body(())?,false)?;
                let stream:Stream=Box::new(Channel {receive:request.into_body(),send,pending:Bytes::new(),ended:false,_owner:None});
                let handler=handler.clone(); let hello=hello.clone(); let child=cancel.child_token();let worker_cancel=cancel.clone();
                clients.spawn(async move { let _=rpc::connection(stream,handler,hello,child,worker_cancel).await; });
            }
        }
    }
    clients.shutdown().await;
    Ok(())
}
/// Hidden CLI entry point; one worker instance handles every logical channel.
pub async fn serve_stdio<H: Handler>(
    hello: Hello,
    handler: Arc<H>,
    cancel: CancellationToken,
) -> Result<()> {
    serve(
        crate::stdio::Pair::new(tokio::io::stdin(), tokio::io::stdout()),
        hello,
        handler,
        cancel,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        catalog::{Artifact, Blob, Component, PROTOCOL, TARGETS},
        rpc::{Client, Failure, Reply},
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[derive(serde::Serialize, serde::Deserialize)]
    enum Operation {
        Increment,
        Stream,
        Wait,
    }
    struct Counter(AtomicUsize);
    #[async_trait::async_trait]
    impl Handler for Counter {
        type Operation = Operation;
        type Value = usize;
        async fn handle(
            &self,
            operation: Operation,
            cancel: CancellationToken,
        ) -> std::result::Result<Reply<usize>, Failure> {
            match operation {
                Operation::Increment => {
                    Ok(Reply::Message(self.0.fetch_add(1, Ordering::SeqCst) + 1))
                }
                Operation::Wait => std::future::pending().await,
                Operation::Stream => {
                    let (local, remote) = tokio::io::duplex(4096);
                    tokio::spawn(async move {
                        let (mut read, mut write) = tokio::io::split(remote);
                        tokio::select! {_=cancel.cancelled()=>{},_ = tokio::io::copy(&mut read,&mut write)=>{}}
                    });
                    Ok(Reply::Stream {
                        value: 0,
                        remote: Box::new(local),
                    })
                }
            }
        }
    }
    fn artifact() -> Artifact {
        Artifact {
            component: Component::Tor,
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
    async fn fixture() -> (
        Arc<Carrier>,
        Arc<Counter>,
        CancellationToken,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let (local, remote) = tokio::io::duplex(8192);
        let artifact = artifact();
        let hello = Hello {
            component: artifact.component,
            protocol: PROTOCOL,
            version: artifact.version,
        };
        let handler = Arc::new(Counter(AtomicUsize::new(0)));
        let cancel = CancellationToken::new();
        let server = tokio::spawn(serve(remote, hello, handler.clone(), cancel.clone()));
        (
            Carrier::connect(local).await.unwrap(),
            handler,
            cancel,
            server,
        )
    }
    #[tokio::test]
    async fn shared_worker_state_and_large_streams_do_not_block_control_channels() -> Result<()> {
        let (carrier, _, cancel, server) = fixture().await;
        let mut first = Client::from_stream(carrier.open().await?, &artifact()).await?;
        let mut second = Client::from_stream(carrier.open().await?, &artifact()).await?;
        assert_eq!(
            first
                .call::<_, usize>(Operation::Increment, Duration::from_secs(1))
                .await?,
            1
        );
        assert_eq!(
            second
                .call::<_, usize>(Operation::Increment, Duration::from_secs(1))
                .await?,
            2
        );
        let streaming = Client::from_stream(carrier.open().await?, &artifact()).await?;
        let (_, stream) = streaming
            .upgrade::<_, usize>(Operation::Stream, Duration::from_secs(1))
            .await?;
        let (mut read, mut write) = tokio::io::split(stream);
        let bytes = vec![42; 2 * 1024 * 1024];
        let expected = bytes.len();
        let writing = tokio::spawn(async move {
            write.write_all(&bytes).await?;
            write.shutdown().await
        });
        assert_eq!(
            second
                .call::<_, usize>(Operation::Increment, Duration::from_secs(1))
                .await?,
            3
        );
        let mut received = vec![];
        tokio::time::timeout(Duration::from_secs(5), read.read_to_end(&mut received)).await??;
        writing.await??;
        assert_eq!(received.len(), expected);
        assert!(received.iter().all(|byte| *byte == 42));
        cancel.cancel();
        server.await??;
        Ok(())
    }
    #[tokio::test]
    async fn unread_upgraded_stream_does_not_exhaust_control_flow_capacity() -> Result<()> {
        let (carrier, _, cancel, server) = fixture().await;
        let connection = Client::from_stream(carrier.open().await?, &artifact()).await?;
        let (_, stream) = connection
            .upgrade::<_, usize>(Operation::Stream, Duration::from_secs(1))
            .await?;
        let (_unread, mut writer) = tokio::io::split(stream);
        let writing =
            tokio::spawn(async move { writer.write_all(&vec![7; 2 * 1024 * 1024]).await });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            !writing.is_finished(),
            "unread stream must apply backpressure"
        );
        let mut control = Client::from_stream(carrier.open().await?, &artifact()).await?;
        assert_eq!(
            control
                .call::<_, usize>(Operation::Increment, Duration::from_secs(1))
                .await?,
            1
        );
        writing.abort();
        let _ = writing.await;
        cancel.cancel();
        server.await??;
        Ok(())
    }
    #[tokio::test]
    async fn interrupted_channel_is_not_replayed_and_other_channels_remain_usable() -> Result<()> {
        let (carrier, handler, cancel, server) = fixture().await;
        let mut stalled = Client::from_stream(carrier.open().await?, &artifact()).await?;
        let result: Result<usize> = stalled
            .call(Operation::Wait, Duration::from_millis(20))
            .await;
        assert!(result.is_err());
        assert!(stalled
            .call::<_, usize>(Operation::Increment, Duration::from_secs(1))
            .await
            .is_err());
        drop(stalled);
        let mut healthy = Client::from_stream(carrier.open().await?, &artifact()).await?;
        assert_eq!(
            healthy
                .call::<_, usize>(Operation::Increment, Duration::from_secs(1))
                .await?,
            1
        );
        assert_eq!(handler.0.load(Ordering::SeqCst), 1);
        cancel.cancel();
        server.await??;
        Ok(())
    }
    #[tokio::test]
    async fn upgraded_stream_retains_carrier_after_original_owner_drops() -> Result<()> {
        let (carrier, _, cancel, server) = fixture().await;
        let weak = Arc::downgrade(&carrier);
        let connection = Client::from_stream(carrier.open().await?, &artifact()).await?;
        let (_, mut stream) = connection
            .upgrade::<_, usize>(Operation::Stream, Duration::from_secs(1))
            .await?;
        drop(carrier);
        assert!(weak.upgrade().is_some());
        stream.write_all(b"retained").await?;
        let mut bytes = [0; 8];
        tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut bytes)).await??;
        assert_eq!(&bytes, b"retained");
        drop(stream);
        assert!(weak.upgrade().is_none());
        cancel.cancel();
        server.await??;
        Ok(())
    }
}
