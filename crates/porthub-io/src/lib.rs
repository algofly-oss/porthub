//! Stream lifetime policy shared by public tunnel endpoints. Full-duplex idle
//! sessions have no deadline; half-closed sessions may finish active responses
//! but cannot hold descriptors forever after both directions stop progressing.
use std::{
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, OnceLock,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Notify,
    time::Instant,
};

pub fn half_close_idle_timeout() -> Duration {
    static TIMEOUT: OnceLock<Duration> = OnceLock::new();
    *TIMEOUT.get_or_init(|| {
        let seconds = match std::env::var("PORTHUB_TUNNEL_HALF_CLOSE_IDLE_SECONDS") {
            Ok(value) => match value.parse::<u64>() {
                Ok(seconds) if seconds <= 86400 => seconds,
                _ => {
                    tracing::warn!("invalid half-close idle timeout; using 120 seconds");
                    120
                }
            },
            Err(_) => 120,
        };
        Duration::from_secs(seconds)
    })
}

struct Activity {
    origin: Instant,
    last: AtomicU64,
    half_closed: AtomicBool,
    closed: Notify,
}
impl Activity {
    fn progress(&self) {
        self.last
            .store(self.origin.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
    fn eof(&self) {
        if !self.half_closed.swap(true, Ordering::Relaxed) {
            self.progress();
            self.closed.notify_one();
        }
    }
    fn idle(&self) -> Duration {
        self.origin
            .elapsed()
            .saturating_sub(Duration::from_millis(self.last.load(Ordering::Relaxed)))
    }
}
struct Observed<'a, T> {
    inner: &'a mut T,
    activity: Arc<Activity>,
}
impl<T: AsyncRead + Unpin> AsyncRead for Observed<'_, T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let capacity = buf.remaining();
        let result = Pin::new(&mut *this.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) && capacity > 0 {
            if buf.filled().len() > before {
                this.activity.progress();
            } else {
                this.activity.eof();
            }
        }
        result
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for Observed<'_, T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut *this.inner).poll_write(cx, bytes);
        if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
            this.activity.progress();
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Preserve TCP half-close semantics and long transfers, but reclaim a copy
/// after EOF followed by `idle` without application reads or writes. Transport
/// heartbeats hidden below AsyncRead do not keep abandoned requests alive.
/// Zero explicitly opts out of this cleanup policy.
pub async fn copy_bidirectional<A, B>(
    a: &mut A,
    b: &mut B,
    idle: Duration,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    if idle.is_zero() {
        return tokio::io::copy_bidirectional(a, b).await;
    }
    let activity = Arc::new(Activity {
        origin: Instant::now(),
        last: AtomicU64::new(0),
        half_closed: AtomicBool::new(false),
        closed: Notify::new(),
    });
    let mut a = Observed {
        inner: a,
        activity: activity.clone(),
    };
    let mut b = Observed {
        inner: b,
        activity: activity.clone(),
    };
    let copy = tokio::io::copy_bidirectional(&mut a, &mut b);
    tokio::pin!(copy);
    tokio::select! {
        biased;
        result = &mut copy => return result,
        _ = activity.closed.notified() => {},
    }
    let deadline = tokio::time::sleep(idle);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            biased;
            result = &mut copy => return result,
            _ = &mut deadline => {
                let elapsed = activity.idle();
                if elapsed >= idle {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "half-closed tunnel stopped making progress"));
                }
                deadline.as_mut().reset(Instant::now() + idle.saturating_sub(elapsed));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    const IDLE: Duration = Duration::from_secs(120);

    #[tokio::test(start_paused = true)]
    async fn abandoned_half_close_is_reclaimed_without_waiting_for_service_refresh() {
        let (mut visitor, mut edge) = duplex(128);
        let (mut agent, mut backend) = duplex(128);
        let forwarding =
            tokio::spawn(async move { copy_bidirectional(&mut edge, &mut agent, IDLE).await });
        visitor.shutdown().await.unwrap();
        assert_eq!(backend.read(&mut [0]).await.unwrap(), 0);
        tokio::time::advance(IDLE + Duration::from_secs(1)).await;
        assert_eq!(
            forwarding.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(visitor.read(&mut [0]).await.unwrap(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn active_response_after_half_close_survives_multiple_idle_windows() {
        let (mut visitor, mut edge) = duplex(128);
        let (mut agent, mut backend) = duplex(128);
        let forwarding =
            tokio::spawn(async move { copy_bidirectional(&mut edge, &mut agent, IDLE).await });
        visitor.shutdown().await.unwrap();
        assert_eq!(backend.read(&mut [0]).await.unwrap(), 0);
        for byte in 0..8 {
            tokio::time::advance(Duration::from_secs(60)).await;
            backend.write_all(&[byte]).await.unwrap();
            let mut received = [0];
            visitor.read_exact(&mut received).await.unwrap();
            assert_eq!(received, [byte]);
        }
        backend.shutdown().await.unwrap();
        assert_eq!(forwarding.await.unwrap().unwrap(), (0, 8));
    }

    #[tokio::test(start_paused = true)]
    async fn quiet_established_connection_has_no_lifetime_limit() {
        let (mut visitor, mut edge) = duplex(128);
        let (mut agent, mut backend) = duplex(128);
        let forwarding =
            tokio::spawn(async move { copy_bidirectional(&mut edge, &mut agent, IDLE).await });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(86400)).await;
        assert!(!forwarding.is_finished());
        visitor.write_all(b"still here").await.unwrap();
        let mut received = [0; 10];
        backend.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"still here");
        visitor.shutdown().await.unwrap();
        backend.shutdown().await.unwrap();
        assert_eq!(forwarding.await.unwrap().unwrap(), (10, 0));
    }
    #[tokio::test(start_paused = true)]
    async fn kernel_half_closed_visitor_is_released_when_the_backend_stays_open() {
        use tokio::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut visitor = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut edge, _) = listener.accept().await.unwrap();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut agent = TcpStream::connect(target.local_addr().unwrap())
            .await
            .unwrap();
        let (mut backend, _) = target.accept().await.unwrap();
        let forwarding =
            tokio::spawn(async move { copy_bidirectional(&mut edge, &mut agent, IDLE).await });
        visitor.shutdown().await.unwrap();
        assert_eq!(backend.read(&mut [0]).await.unwrap(), 0);
        tokio::time::advance(IDLE + Duration::from_secs(1)).await;
        assert_eq!(
            forwarding.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(visitor.read(&mut [0]).await.unwrap(), 0);
    }
}
