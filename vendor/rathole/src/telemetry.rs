//! Application-byte counters updated as I/O progresses, rather than only when
//! a transfer closes. No payload, endpoint credential or history is retained.
use std::{
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
pub(crate) struct Counters {
    active: AtomicU64,
    sent: AtomicU64,
    received: AtomicU64,
}
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct Traffic {
    pub active_channels: u64,
    pub sent_bytes: u64,
    pub received_bytes: u64,
}
impl Counters {
    pub(crate) fn snapshot(&self) -> Traffic {
        Traffic {
            active_channels: self.active.load(Ordering::Acquire),
            sent_bytes: self.sent.load(Ordering::Relaxed),
            received_bytes: self.received.load(Ordering::Relaxed),
        }
    }
    pub(crate) fn sent(&self, bytes: usize) {
        self.sent.fetch_add(bytes as u64, Ordering::Relaxed);
    }
    pub(crate) fn received(&self, bytes: usize) {
        self.received.fetch_add(bytes as u64, Ordering::Relaxed);
    }
    pub(crate) fn enter(self: &Arc<Self>) -> Active {
        self.active.fetch_add(1, Ordering::Relaxed);
        Active(self.clone())
    }
    pub(crate) fn meter<T>(self: &Arc<Self>, inner: T) -> Metered<T> {
        Metered {
            inner,
            active: self.enter(),
        }
    }
}
pub(crate) struct Active(Arc<Counters>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Release);
    }
}
pub(crate) struct Metered<T> {
    inner: T,
    active: Active,
}
impl<T: AsyncRead + Unpin> AsyncRead for Metered<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buffer);
        if matches!(result, Poll::Ready(Ok(()))) {
            this.active.0.sent(buffer.filled().len() - before);
        }
        result
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for Metered<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, bytes);
        if let Poll::Ready(Ok(size)) = &result {
            this.active.0.received(*size);
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn counts_live_partial_io_and_releases_channels_on_disconnect() -> io::Result<()> {
        let counters = Arc::new(Counters::default());
        let (local, mut app) = tokio::io::duplex(1024);
        let mut metered = counters.meter(local);
        app.write_all(b"reply").await?;
        let mut bytes = [0; 5];
        metered.read_exact(&mut bytes).await?;
        metered.write_all(b"request").await?;
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.sent_bytes, 5);
        assert_eq!(snapshot.received_bytes, 7);
        assert_eq!(snapshot.active_channels, 1);
        drop(metered);
        assert_eq!(counters.snapshot().active_channels, 0);
        Ok(())
    }
}
