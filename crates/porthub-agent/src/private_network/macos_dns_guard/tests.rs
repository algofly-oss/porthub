use super::*;
use std::os::fd::AsFd;

#[tokio::test]
async fn descriptor_transfer_is_ordered_cloexec_and_preserves_both_queues() -> Result<()> {
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let addr = udp.local_addr()?;
    let tcp = TcpListener::bind(addr)?;
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    peer.send_to(b"question", addr)?;
    let mut client = tokio::net::TcpStream::connect(addr).await?;
    client.write_all(b"tcp question").await?;
    udp.set_nonblocking(true)?;
    tcp.set_nonblocking(true)?;
    let pair = (
        File::from(OwnedFd::from(udp)),
        File::from(OwnedFd::from(tcp)),
    );
    let (left, right) = UnixStream::pair()?;
    ipc::send(&left, &pair).await?;
    drop(pair);
    let (udp, tcp) = ipc::receive(&right).await?;
    for fd in [udp.as_fd(), tcp.as_fd()] {
        ensure!(rustix::io::fcntl_getfd(fd)?.contains(rustix::io::FdFlags::CLOEXEC));
    }
    let socket = tokio::net::UdpSocket::from_std(UdpSocket::from(OwnedFd::from(udp)))?;
    let listener = tokio::net::TcpListener::from_std(TcpListener::from(OwnedFd::from(tcp)))?;
    ensure!(socket.local_addr()? == addr && listener.local_addr()? == addr);
    let mut query = [0; 12];
    let (n, _) = socket.recv_from(&mut query).await?;
    ensure!(&query[..n] == b"question");
    listener.accept().await?.0.read_exact(&mut query).await?;
    ensure!(&query == b"tcp question");
    Ok(())
}

#[tokio::test]
async fn malformed_or_oversized_local_protocol_cannot_return_descriptors() -> Result<()> {
    let (mut left, mut right) = UnixStream::pair()?;
    left.write_all(&u16::MAX.to_be_bytes()).await?;
    ensure!(ipc::read(&mut right).await.is_err());
    left.write_all(b"1").await?;
    ensure!(ipc::receive(&right).await.is_err());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires root on macOS to register a unique temporary .test suffix"]
async fn crash_queue_requires_matching_identity_expires_and_withdraws_on_stop() -> Result<()> {
    use std::os::unix::net::UnixStream as StdControl;
    use tokio::net::UnixListener;
    ensure!(rustix::process::geteuid().is_root());
    async fn connect(path: &Path, request: &Claim) -> Result<(StdControl, String, (File, File))> {
        let mut control = UnixStream::connect(path).await?;
        ipc::write(&mut control, &serde_json::to_vec(request)?).await?;
        let key = String::from_utf8(ipc::read(&mut control).await?)?;
        let fds = ipc::receive(&control).await?;
        Ok((control.into_std()?, key, fds))
    }
    let root = tempfile::tempdir()?;
    let path = root.path().join("ctrl");
    let suffixes = vec![format!("ph-guard-{}.test", uuid::Uuid::new_v4().simple())];
    let mut request = Claim {
        binding: "a".repeat(64),
        suffixes: suffixes.clone(),
    };
    let listener = UnixListener::bind(&path)?;
    let job = tokio::spawn(serve(listener, |pid| {
        std::future::ready(Ok(pid == std::process::id()))
    }));
    let (first, key, (udp, tcp)) = connect(&path, &request).await?;
    let udp = UdpSocket::from(OwnedFd::from(udp));
    let first_addr = udp.local_addr()?;
    drop((first, udp, tcp));
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    sender.send_to(b"queued", first_addr)?;
    let (second, new_key, (udp, tcp)) = connect(&path, &request).await?;
    ensure!(
        key == new_key,
        "same enrollment lost the original resolver key"
    );
    let udp = tokio::net::UdpSocket::from_std(UdpSocket::from(OwnedFd::from(udp)))?;
    let mut query = [0; 6];
    ensure!(udp.recv_from(&mut query).await?.0 == 6 && query == *b"queued");
    drop((second, udp, tcp));
    sender.send_to(b"secret", first_addr)?;
    request.binding = "b".repeat(64);
    let (third, third_key, (udp, tcp)) = connect(&path, &request).await?;
    ensure!(
        third_key != key,
        "another enrollment received the prior DNS registration"
    );
    let udp = tokio::net::UdpSocket::from_std(UdpSocket::from(OwnedFd::from(udp)))?;
    ensure!(
        udp.try_recv_from(&mut query).is_err(),
        "another enrollment inherited queued questions"
    );
    let port = udp.local_addr()?.port();
    let mut control = UnixStream::from_std(third)?;
    control.write_all(b"X").await?;
    ensure!(control.read_u8().await? == b'X');
    job.await??;
    drop((control, udp, tcp));
    convergence::wait(
        &[],
        &[Endpoint {
            suffix: suffixes[0].clone(),
            port,
        }],
    )
    .await?;
    std::fs::remove_file(&path)?;
    let listener = UnixListener::bind(&path)?;
    let job = tokio::spawn(serve(listener, |pid| {
        std::future::ready(Ok(pid == std::process::id()))
    }));
    let (control, _, (udp, tcp)) = connect(&path, &request).await?;
    let endpoint = UdpSocket::from(OwnedFd::from(udp)).local_addr()?;
    drop((control, tcp));
    tokio::time::timeout(WINDOW + Duration::from_secs(10), job).await???;
    convergence::wait(
        &[],
        &[Endpoint {
            suffix: suffixes[0].clone(),
            port: endpoint.port(),
        }],
    )
    .await?;
    ensure!(UdpSocket::bind(endpoint).is_ok() && TcpListener::bind(endpoint).is_ok());
    Ok(())
}

#[tokio::test]
async fn client_waits_for_the_launchd_socket_to_appear() -> Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("ctrl");
    let connecting = tokio::spawn({
        let path = path.clone();
        async move { ipc::connect(&path).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let listener = tokio::net::UnixListener::bind(&path)?;
    tokio::time::timeout(Duration::from_secs(2), listener.accept()).await??;
    connecting.await??;
    Ok(())
}

#[tokio::test]
async fn reversed_socket_roles_cannot_be_adopted() -> Result<()> {
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let tcp = TcpListener::bind(udp.local_addr()?)?;
    let reversed = (
        File::from(OwnedFd::from(tcp)),
        File::from(OwnedFd::from(udp)),
    );
    let (left, right) = UnixStream::pair()?;
    ipc::send(&left, &reversed).await?;
    ensure!(ipc::receive(&right).await.is_err());
    Ok(())
}
