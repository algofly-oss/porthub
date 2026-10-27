//! Bounded stream carrier on the existing API connection. Its forwarding task
//! belongs to the returned stream and is cancelled when that stream is dropped.
use crate::BoxStream;
use futures_util::{SinkExt, StreamExt};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};

struct OwnedStream {
    stream: DuplexStream,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for OwnedStream {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl AsyncRead for OwnedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buffer)
    }
}
impl AsyncWrite for OwnedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buffer)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
pub fn stream<S>(socket: WebSocketStream<S>) -> anyhow::Result<BoxStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    anyhow::ensure!(
        socket
            .get_config()
            .max_message_size
            .is_some_and(|limit| limit <= 64 * 1024)
            && socket
                .get_config()
                .max_frame_size
                .is_some_and(|limit| limit <= 64 * 1024),
        "proxy carrier requires bounded WebSocket frames"
    );
    let (local, remote) = tokio::io::duplex(32 * 1024);
    let task = tokio::spawn(async move {
        let (mut outgoing, mut incoming) = socket.split();
        let (mut reader, mut writer) = tokio::io::split(remote);
        let upload = async {
            let mut buffer = [0u8; 16 * 1024];
            loop {
                let size = reader.read(&mut buffer).await.map_err(|_| ())?;
                if size == 0 {
                    outgoing
                        .send(Message::Text("eof".into()))
                        .await
                        .map_err(|_| ())?;
                    return Ok::<_, ()>(());
                }
                outgoing
                    .send(Message::Binary(buffer[..size].to_vec().into()))
                    .await
                    .map_err(|_| ())?;
            }
        };
        let download = async {
            while let Some(message) = incoming.next().await {
                match message.map_err(|_| ())? {
                    Message::Binary(bytes) if bytes.len() <= 64 * 1024 => {
                        writer.write_all(&bytes).await.map_err(|_| ())?
                    }
                    Message::Text(text) if text == "eof" => {
                        writer.shutdown().await.map_err(|_| ())?;
                        return Ok::<_, ()>(());
                    }
                    Message::Ping(_) | Message::Pong(_) => {}
                    _ => return Err(()),
                }
            }
            Err(())
        };
        let _ = tokio::try_join!(upload, download);
    });
    Ok(Box::new(OwnedStream {
        stream: local,
        task,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};
    #[tokio::test]
    async fn carries_backpressured_streams_and_tcp_half_close() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
            let mut count = 0;
            while let Some(message) = socket.next().await {
                match message.unwrap() {
                    Message::Binary(bytes) => {
                        count += bytes.len();
                        assert!(bytes.iter().all(|byte| *byte == 71));
                    }
                    Message::Text(text) if text == "eof" => break,
                    _ => panic!("unexpected stream message"),
                }
            }
            assert_eq!(count, 2 * 1024 * 1024);
            socket
                .send(Message::Binary(b"half-close response".to_vec().into()))
                .await
                .unwrap();
            socket.send(Message::Text("eof".into())).await.unwrap();
        });
        let socket = TcpStream::connect(address).await.unwrap();
        let (socket, _) = tokio_tungstenite::client_async_with_config(
            format!("ws://{address}/"),
            socket,
            Some(
                tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
                    .max_message_size(Some(65536))
                    .max_frame_size(Some(65536)),
            ),
        )
        .await
        .unwrap();
        let mut io = stream(socket).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            io.write_all(&vec![71; 2 * 1024 * 1024]).await.unwrap();
            io.shutdown().await.unwrap();
            let mut response = Vec::new();
            io.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"half-close response");
            server.await.unwrap();
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn dropping_local_stream_closes_its_remote_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
            assert!(!matches!(socket.next().await, Some(Ok(Message::Binary(_)))));
        });
        let socket = TcpStream::connect(address).await.unwrap();
        let (socket, _) = tokio_tungstenite::client_async_with_config(
            format!("ws://{address}/"),
            socket,
            Some(
                tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
                    .max_message_size(Some(65536))
                    .max_frame_size(Some(65536)),
            ),
        )
        .await
        .unwrap();
        drop(stream(socket).unwrap());
        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }
}
