use std::{
    io,
    os::fd::AsRawFd,
    pin::Pin,
    task::{ready, Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, Interest, ReadBuf},
    net::TcpStream,
};

// Defined by the macOS SDK in netinet/tcp.h.
const TCP_NOTSENT_LOWAT: libc::c_int = 0x201;
const UNSENT_LOW_WATER_BYTES: libc::c_uint = 64 * 1024;
const WRITE_BUDGET_BYTES: usize = 16 * 1024;

pub(super) struct WriteQueue {
    stream: TcpStream,
    budget: Option<usize>,
}

impl WriteQueue {
    pub(super) fn new(stream: TcpStream) -> Self {
        let result = unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::IPPROTO_TCP,
                TCP_NOTSENT_LOWAT,
                (&UNSENT_LOW_WATER_BYTES as *const libc::c_uint).cast(),
                std::mem::size_of_val(&UNSENT_LOW_WATER_BYTES) as libc::socklen_t,
            )
        };
        Self {
            stream,
            budget: (result == 0).then_some(0),
        }
    }

    fn poll_writable(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            ready!(self.stream.poll_write_ready(cx))?;
            let result = self.stream.try_io(Interest::WRITABLE, || {
                // Darwin applies the unsent limit to write readiness. Tokio may
                // still cache an earlier ready indication after successful writes.
                let mut descriptor = libc::pollfd {
                    fd: self.stream.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                };
                loop {
                    let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
                    if result > 0 {
                        return Ok(());
                    }
                    if result == 0 {
                        return Err(io::ErrorKind::WouldBlock.into());
                    }
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::Interrupted {
                        return Err(error);
                    }
                }
            });
            match result {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                other => return Poll::Ready(other),
            }
        }
    }
}

impl AsyncRead for WriteQueue {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buffer)
    }
}

impl AsyncWrite for WriteQueue {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let Some(mut budget) = self.budget else {
            return Pin::new(&mut self.stream).poll_write(cx, bytes);
        };
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if budget == 0 {
            ready!(self.poll_writable(cx))?;
            budget = WRITE_BUDGET_BYTES;
        }
        let written =
            ready!(Pin::new(&mut self.stream).poll_write(cx, &bytes[..bytes.len().min(budget)]))?;
        self.budget = Some(budget - written);
        Poll::Ready(Ok(written))
    }

    fn is_write_vectored(&self) -> bool {
        self.budget.is_none() && self.stream.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if self.budget.is_none() {
            return Pin::new(&mut self.stream).poll_write_vectored(cx, buffers);
        }
        self.poll_write(
            cx,
            buffers
                .iter()
                .find(|buf| !buf.is_empty())
                .map_or(&[], |buf| &**buf),
        )
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;
    use std::{future::poll_fn, time::Duration};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn backpressure_bounds_writes_and_resumes_after_the_peer_drains() -> anyhow::Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        socket2::SockRef::from(&listener).set_recv_buffer_size(128 * 1024)?;
        let stream = TcpStream::connect(listener.local_addr()?).await?;
        socket2::SockRef::from(&stream).set_send_buffer_size(3 * 1024 * 1024)?;
        let (mut peer, _) = listener.accept().await?;
        let mut sender = WriteQueue::new(stream);
        ensure!(
            sender.budget.is_some(),
            "macOS did not enable the unsent limit"
        );
        let queued = tokio::task::unconstrained(poll_fn(|cx| {
            let mut queued = 0;
            while queued < 3 * 1024 * 1024 {
                match Pin::new(&mut sender).poll_write(cx, &[1; 1400]) {
                    Poll::Ready(Ok(n)) if n > 0 => queued += n,
                    Poll::Ready(Ok(_)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => break,
                }
            }
            Poll::Ready(Ok(queued))
        }))
        .await?;
        ensure!((1..1024 * 1024).contains(&queued), "queued {queued} bytes");
        let mut received = vec![0; queued + 1];
        tokio::time::timeout(Duration::from_secs(3), async {
            tokio::try_join!(sender.write_all(&[2]), peer.read_exact(&mut received))
        })
        .await??;
        ensure!(received[..queued].iter().all(|byte| *byte == 1));
        ensure!(received[queued] == 2);
        Ok(())
    }
}
