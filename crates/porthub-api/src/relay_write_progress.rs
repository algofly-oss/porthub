//! Count actual transport progress when a TURN WebSocket write is backpressured.
use axum::{
    extract::connect_info::Connected,
    serve::{IncomingStream, Listener},
};
use std::{
    io,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::watch,
    time::Instant,
};

#[derive(Clone, Default)]
pub struct WriteProgress(Arc<OnceLock<watch::Sender<Instant>>>);

impl WriteProgress {
    pub(crate) fn observe(&self) -> watch::Receiver<Instant> {
        self.0
            .get_or_init(|| watch::Sender::new(Instant::now()))
            .subscribe()
    }

    fn wrote(&self, n: usize) {
        if n != 0 {
            if let Some(clock) = self.0.get() {
                if clock.receiver_count() > 0 {
                    clock.send_replace(Instant::now());
                }
            }
        }
    }
}

pub struct MeasuredListener<L>(pub L);

pub struct MeasuredIo<I> {
    inner: I,
    progress: WriteProgress,
}

impl<I> MeasuredIo<I> {
    pub(crate) fn new(inner: I, progress: WriteProgress) -> Self {
        Self { inner, progress }
    }
}

impl<L: Listener> Listener for MeasuredListener<L> {
    type Io = MeasuredIo<L::Io>;
    type Addr = L::Addr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let (io, addr) = self.0.accept().await;
        (MeasuredIo::new(io, WriteProgress::default()), addr)
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.0.local_addr()
    }
}

impl<L: Listener> Connected<IncomingStream<'_, MeasuredListener<L>>> for WriteProgress {
    fn connect_info(stream: IncomingStream<'_, MeasuredListener<L>>) -> Self {
        stream.io().progress.clone()
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for MeasuredIo<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for MeasuredIo<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let n = std::task::ready!(Pin::new(&mut self.inner).poll_write(cx, buf))?;
        self.progress.wrote(n);
        Poll::Ready(Ok(n))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let n = std::task::ready!(Pin::new(&mut self.inner).poll_write_vectored(cx, bufs))?;
        self.progress.wrote(n);
        Poll::Ready(Ok(n))
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(all(test, unix))]
#[tokio::test]
async fn unix_api_reports_bytes_written_on_its_own_connection() {
    use axum::{extract::ConnectInfo, routing::get, Router};
    use std::{future::IntoFuture, time::Duration};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{UnixListener, UnixStream},
        sync::mpsc,
    };

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("core.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let (tx, mut rx) = mpsc::channel(2);
    let router = Router::new().route(
        "/",
        get(move |ConnectInfo(progress): ConnectInfo<WriteProgress>| {
            let tx = tx.clone();
            async move {
                let clock = progress.observe();
                tx.send((progress, clock)).await.unwrap();
                "ready"
            }
        }),
    );
    let service = router.into_make_service_with_connect_info::<WriteProgress>();
    let server = tokio::spawn(axum::serve(MeasuredListener(listener), service).into_future());
    let mut previous = None;
    for _ in 0..2 {
        let mut client = UnixStream::connect(&path).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.ends_with(b"ready"));
        let (progress, mut clock) = rx.recv().await.unwrap();
        assert!(clock.has_changed().unwrap());
        clock.borrow_and_update();
        if let Some((old_progress, old_clock)) = previous.take() {
            assert!(!Arc::ptr_eq(&progress.0, &old_progress));
            let old_clock: watch::Receiver<Instant> = old_clock;
            assert!(!old_clock.has_changed().unwrap());
        }
        previous = Some((progress.0, clock));
    }
    server.abort();
}
