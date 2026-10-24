//! PortHub's versioned byte-stream framing. EOF closes only the write direction;
//! the underlying connection remains readable until the peer also finishes.
use std::future::Future;
use std::{
    io,
    pin::Pin,
    task::{ready, Context, Poll, Waker},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

pub const SUBPROTOCOL: &str = "porthub.tcp.v1";
pub const WEBSOCKET_FRAME_SIZE: usize = 64 * 1024;
pub const DIRECT_FRAME_SIZE: usize = 1024 * 1024;

#[derive(Debug)]
pub struct FramedIo<S> {
    inner: S,
    limit: usize,
    header: [u8; 5],
    header_read: usize,
    remaining: usize,
    read_eof: bool,
    pending: Vec<u8>,
    written: usize,
    write_eof: bool,
    heartbeat: Option<Heartbeat>,
}

#[derive(Debug)]
struct Heartbeat {
    timer: Pin<Box<Sleep>>,
    interval: Duration,
    flushing: bool,
    writer_waiter: Option<Waker>,
}

impl<S> FramedIo<S> {
    pub fn new(inner: S, limit: usize) -> Self {
        assert!(limit > 0 && limit <= DIRECT_FRAME_SIZE);
        Self {
            inner,
            limit,
            header: [0; 5],
            header_read: 0,
            remaining: 0,
            read_eof: false,
            pending: Vec::new(),
            written: 0,
            write_eof: false,
            heartbeat: None,
        }
    }

    /// Keep proxy-facing pooled channels alive while waiting for the peer.
    /// The reader drives this timer; no extra task or application bytes are used.
    pub fn with_keepalive(inner: S, limit: usize, interval: Duration) -> Self {
        assert!(!interval.is_zero());
        let mut stream = Self::new(inner, limit);
        stream.heartbeat = Some(Heartbeat {
            timer: Box::pin(tokio::time::sleep(interval)),
            interval,
            flushing: false,
            writer_waiter: None,
        });
        stream
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn truncated() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "tunnel ended before framed EOF",
    )
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for FramedIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 || this.read_eof {
            return Poll::Ready(Ok(()));
        }
        // A blocked heartbeat writer must never prevent reading: both peers may
        // have full outgoing buffers and need reads to relieve backpressure.
        if let Poll::Ready(Err(error)) = this.poll_heartbeat(cx) {
            return Poll::Ready(Err(error));
        }
        // Bound work on heartbeat-only streams so cancellation remains responsive.
        for _ in 0..32 {
            if this.remaining > 0 {
                let count = this.remaining.min(buf.remaining());
                let mut part = ReadBuf::new(buf.initialize_unfilled_to(count));
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut part))?;
                let n = part.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(truncated()));
                }
                buf.advance(n);
                this.remaining -= n;
                return Poll::Ready(Ok(()));
            }
            while this.header_read < 5 {
                let mut header = ReadBuf::new(&mut this.header[this.header_read..]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut header))?;
                let n = header.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(truncated()));
                }
                this.header_read += n;
            }
            let length = u32::from_be_bytes(this.header[1..].try_into().unwrap()) as usize;
            this.header_read = 0;
            match (this.header[0], length) {
                (0, n) if n > 0 && n <= this.limit => this.remaining = n,
                (1, 0) => {
                    this.read_eof = true;
                    return Poll::Ready(Ok(()));
                }
                (2, 0) => {}
                _ => return Poll::Ready(Err(invalid("invalid tunnel frame"))),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<S: AsyncWrite + Unpin> FramedIo<S> {
    fn postpone_heartbeat(&mut self) {
        if let Some(heartbeat) = &mut self.heartbeat {
            heartbeat
                .timer
                .as_mut()
                .reset(Instant::now() + heartbeat.interval);
        }
    }

    fn finish_heartbeat(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self
            .heartbeat
            .as_ref()
            .is_some_and(|heartbeat| heartbeat.flushing)
        {
            ready!(self.drain(cx))?;
            ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
            self.heartbeat.as_mut().unwrap().flushing = false;
            if let Some(writer) = self.heartbeat.as_mut().unwrap().writer_waiter.take() {
                writer.wake();
            }
            self.postpone_heartbeat();
        }
        Poll::Ready(Ok(()))
    }

    fn finish_heartbeat_for_writer(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = self.finish_heartbeat(cx);
        if result.is_pending() {
            // A split reader can finish the same heartbeat using a different
            // task waker. Preserve the application writer's wakeup as well.
            self.heartbeat.as_mut().unwrap().writer_waiter = Some(cx.waker().clone());
        }
        result
    }

    fn poll_heartbeat(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.finish_heartbeat(cx))?;
        if !self.write_eof {
            if let Some(heartbeat) = &mut self.heartbeat {
                if heartbeat.timer.as_mut().poll(cx).is_ready() {
                    if self.pending.is_empty() {
                        self.pending.extend_from_slice(&[2, 0, 0, 0, 0]);
                        heartbeat.flushing = true;
                    } else {
                        // An application frame owns the writer until drained.
                        self.postpone_heartbeat();
                    }
                    ready!(self.finish_heartbeat(cx))?;
                    // Register the next deadline even if the whole heartbeat
                    // flushed immediately and this read remains pending.
                    let _ = self.heartbeat.as_mut().unwrap().timer.as_mut().poll(cx);
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.pending.len() {
            let n =
                ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.written..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.written += n;
        }
        self.pending.clear();
        self.written = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FramedIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_eof {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(this.finish_heartbeat_for_writer(cx))?;
        ready!(this.drain(cx))?;
        let n = bytes.len().min(this.limit);
        this.pending.push(0);
        this.pending.extend_from_slice(&(n as u32).to_be_bytes());
        this.pending.extend_from_slice(&bytes[..n]);
        this.postpone_heartbeat();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.finish_heartbeat_for_writer(cx))?;
        ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.finish_heartbeat_for_writer(cx))?;
        if !this.write_eof {
            ready!(this.drain(cx))?;
            this.pending.extend_from_slice(&[1, 0, 0, 0, 0]);
            this.write_eof = true;
        }
        ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }
}
