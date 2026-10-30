use porthub_tunnel::{FramedIo, DIRECT_FRAME_SIZE, WEBSOCKET_FRAME_SIZE};
use std::{io::ErrorKind, time::Duration};
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

// This is a protocol/deadlock check over an entirely in-memory stream. The
// virtual clock advances to the deadline only when no task can make progress;
// a slow shared CI runner must not turn seven-byte scheduling into a failure.
#[tokio::test(start_paused = true)]
async fn half_close_keeps_response_readable_under_backpressure() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (a, b) = duplex(7);
        let mut client = FramedIo::new(a, WEBSOCKET_FRAME_SIZE);
        let mut server = FramedIo::new(b, WEBSOCKET_FRAME_SIZE);
        let payload = vec![179; WEBSOCKET_FRAME_SIZE * 3 + 1];
        let expected = payload.clone();
        let responder = tokio::spawn(async move {
            let mut request = Vec::new();
            server.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, expected);
            server
                .write_all(b"response after request EOF")
                .await
                .unwrap();
            server.shutdown().await.unwrap();
            server.shutdown().await.unwrap();
            assert_eq!(
                server.write(b"late").await.unwrap_err().kind(),
                ErrorKind::BrokenPipe
            );
        });
        client.write_all(&payload).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"response after request EOF");
        responder.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn wire_encoding_matches_existing_go_agent() {
    let (a, mut b) = duplex(128);
    let mut framed = FramedIo::new(a, DIRECT_FRAME_SIZE);
    framed.write_all(b"abc").await.unwrap();
    framed.shutdown().await.unwrap();
    let mut wire = [0; 13];
    b.read_exact(&mut wire).await.unwrap();
    assert_eq!(wire, [0, 0, 0, 0, 3, b'a', b'b', b'c', 1, 0, 0, 0, 0]);
    // Heartbeats do not surface as application bytes. The write side may have
    // finished while the peer is still returning a response.
    b.write_all(&[2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 42, 1, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut received = Vec::new();
    framed.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, [42]);
}

#[tokio::test]
async fn invalid_and_truncated_frames_are_rejected() {
    for (wire, kind) in [
        (vec![0, 0, 0, 0, 0], ErrorKind::InvalidData),
        (vec![3, 0, 0, 0, 0], ErrorKind::InvalidData),
        (vec![1, 0, 0, 0, 1], ErrorKind::InvalidData),
        (vec![0, 0, 1, 0, 1], ErrorKind::InvalidData),
        (vec![0, 0, 0], ErrorKind::UnexpectedEof),
        (vec![0, 0, 0, 0, 3, 42], ErrorKind::UnexpectedEof),
        (vec![], ErrorKind::UnexpectedEof),
    ] {
        let (a, mut b) = duplex(128);
        b.write_all(&wire).await.unwrap();
        b.shutdown().await.unwrap();
        let mut framed = FramedIo::new(a, WEBSOCKET_FRAME_SIZE);
        let error = framed.read_to_end(&mut Vec::new()).await.unwrap_err();
        assert_eq!(error.kind(), kind, "wire {wire:?}");
    }
}

#[tokio::test]
async fn cancelled_read_retains_partial_header() {
    let (a, mut b) = duplex(128);
    let mut framed = FramedIo::new(a, WEBSOCKET_FRAME_SIZE);
    b.write_all(&[0, 0, 0]).await.unwrap();
    let mut byte = [0];
    assert!(
        tokio::time::timeout(Duration::from_millis(10), framed.read(&mut byte))
            .await
            .is_err()
    );
    b.write_all(&[0, 1, 77]).await.unwrap();
    framed.read_exact(&mut byte).await.unwrap();
    assert_eq!(byte, [77]);
}

#[tokio::test(start_paused = true)]
async fn idle_reader_emits_repeated_heartbeats_without_application_bytes() {
    use futures_util::poll;
    let (a, mut b) = duplex(128);
    let mut framed = FramedIo::with_keepalive(a, WEBSOCKET_FRAME_SIZE, Duration::from_secs(15));
    let mut byte = [0];
    let mut waiting = Box::pin(framed.read(&mut byte));
    assert!(poll!(&mut waiting).is_pending());
    for _ in 0..3 {
        tokio::time::advance(Duration::from_secs(15)).await;
        assert!(poll!(&mut waiting).is_pending());
        let mut heartbeat = [0; 5];
        b.read_exact(&mut heartbeat).await.unwrap();
        assert_eq!(heartbeat, [2, 0, 0, 0, 0]);
    }
    b.write_all(&[0, 0, 0, 0, 1, 42]).await.unwrap();
    assert_eq!(waiting.await.unwrap(), 1);
    assert_eq!(byte, [42]);
    framed.shutdown().await.unwrap();
    let mut eof = [0; 5];
    b.read_exact(&mut eof).await.unwrap();
    assert_eq!(eof, [1, 0, 0, 0, 0]);
}

#[tokio::test(start_paused = true)]
async fn simultaneous_partial_heartbeats_cannot_deadlock_bidirectional_forwarding() {
    use futures_util::poll;
    tokio::time::timeout(Duration::from_secs(120), async {
        let (a, b) = duplex(1);
        let mut a = FramedIo::with_keepalive(a, WEBSOCKET_FRAME_SIZE, Duration::from_secs(15));
        let mut b = FramedIo::with_keepalive(b, WEBSOCKET_FRAME_SIZE, Duration::from_secs(15));
        // Both outgoing heartbeat frames become partially written before an
        // application starts using the pooled channel.
        let (mut first, mut second) = ([0], [0]);
        {
            let mut ar = Box::pin(a.read(&mut first));
            let mut br = Box::pin(b.read(&mut second));
            assert!(poll!(&mut ar).is_pending());
            assert!(poll!(&mut br).is_pending());
            tokio::time::advance(Duration::from_secs(15)).await;
            assert!(poll!(&mut ar).is_pending());
            assert!(poll!(&mut br).is_pending());
        }
        async fn exchange(stream: FramedIo<tokio::io::DuplexStream>, value: u8, expected: u8) {
            let (mut reader, mut writer) = tokio::io::split(stream);
            let sending = tokio::spawn(async move {
                writer.write_all(&vec![value; 4096]).await.unwrap();
                writer.shutdown().await.unwrap();
            });
            let receiving = tokio::spawn(async move {
                let mut bytes = Vec::new();
                reader.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, vec![expected; 4096]);
            });
            let (sent, received) = tokio::join!(sending, receiving);
            sent.unwrap();
            received.unwrap();
        }
        tokio::join!(exchange(a, 17, 43), exchange(b, 43, 17));
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn silent_open_carrier_expires_but_heartbeats_keep_an_idle_carrier_healthy() {
    use futures_util::poll;
    let (server, mut peer) = duplex(128);
    let mut server = FramedIo::with_read_timeout(server, WEBSOCKET_FRAME_SIZE, Duration::from_secs(60));
    let mut byte = [0];
    let mut waiting = Box::pin(server.read(&mut byte));
    assert!(poll!(&mut waiting).is_pending());
    for _ in 0..8 {
        tokio::time::advance(Duration::from_secs(15)).await;
        peer.write_all(&[2, 0, 0, 0, 0]).await.unwrap();
        assert!(poll!(&mut waiting).is_pending());
    }
    // Keep both socket halves open but stop delivering bytes, as a blackhole
    // would. No socket EOF is available to rescue the old pool.
    tokio::time::advance(Duration::from_secs(61)).await;
    assert_eq!(waiting.await.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
}
