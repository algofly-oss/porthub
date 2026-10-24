//! Byte-stream adapter for the shared HTTP listener. Forwarding remains in
//! Rathole; this module handles only WebSocket message boundaries.
use axum::extract::ws::{Message, WebSocket};
use futures_util::{Sink, Stream};
use std::{
    io,
    pin::Pin,
    task::{ready, Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug)]
pub struct WebSocketIo {
    socket: WebSocket,
    pending: axum::body::Bytes,
    closed: bool,
}

impl WebSocketIo {
    pub fn new(socket: WebSocket) -> Self {
        Self {
            socket,
            pending: Default::default(),
            closed: false,
        }
    }
}

fn error(e: axum::Error) -> io::Error {
    io::Error::other(e)
}

impl AsyncRead for WebSocketIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !this.pending.is_empty() {
                let n = buf.remaining().min(this.pending.len());
                buf.put_slice(&this.pending.split_to(n));
                return Poll::Ready(Ok(()));
            }
            if this.closed {
                return Poll::Ready(Ok(()));
            }
            // Also flush automatic Pong replies queued by tungstenite.
            ready!(Pin::new(&mut this.socket).poll_flush(cx)).map_err(error)?;
            match ready!(Pin::new(&mut this.socket).poll_next(cx)) {
                Some(Ok(Message::Binary(bytes))) => this.pending = bytes,
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                Some(Ok(Message::Close(_))) | None => this.closed = true,
                Some(Ok(Message::Text(_))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "binary tunnel frames required",
                    )))
                }
                Some(Err(e)) => return Poll::Ready(Err(error(e))),
            }
        }
    }
}

impl AsyncWrite for WebSocketIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(Pin::new(&mut this.socket).poll_ready(cx)).map_err(error)?;
        let n = buf.len().min(64 * 1024);
        if n == 0 {
            return Poll::Ready(Ok(0));
        }
        Pin::new(&mut this.socket)
            .start_send(Message::Binary(buf[..n].to_vec().into()))
            .map_err(error)?;
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket)
            .poll_flush(cx)
            .map_err(error)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket)
            .poll_close(cx)
            .map_err(error)
    }
}
