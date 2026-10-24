use anyhow::Result;
use porthub_tunnel::{gateway_config, EmbeddedServer, FramedIo, DIRECT_FRAME_SIZE};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::RwLock,
};

#[tokio::test]
async fn upgrade_preserves_pipelined_hello_and_returns_authentication_failures() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let config = gateway_config("[server.services.test]\ntoken='secret'\nbind_addr='127.0.0.1:0'\n")?;
        let server = Arc::new(RwLock::new(EmbeddedServer::new(config).await?));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let router = porthub_edge::router(server.clone());
        let serving = tokio::spawn(async move { axum::serve(listener, router).await });
        for (name, ack) in [("missing", 1u32), ("test", 2u32)] {
            let mut tcp = TcpStream::connect(address).await?;
            let mut request = b"GET /api/tunnel HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive, UpGrAdE\r\nUpgrade: porthub.tcp.v1\r\n\r\n".to_vec();
            // Existing Go/bincode wire bytes, independent of Rust's serializer.
            let mut hello = vec![0,0,0,0,1];
            hello.extend_from_slice(&Sha256::digest(name.as_bytes()));
            request.extend_from_slice(&[0,0,0,0,37]);
            request.extend_from_slice(&hello);
            tcp.write_all(&request).await?;
            let mut reader = BufReader::new(tcp);
            let mut header = String::new();
            loop {
                let n = reader.read_line(&mut header).await?;
                assert_ne!(n, 0);
                if header.ends_with("\r\n\r\n") { break; }
            }
            assert!(header.starts_with("HTTP/1.1 101"), "{header}");
            assert!(header.to_ascii_lowercase().contains("upgrade: porthub.tcp.v1"));
            let mut io = FramedIo::new(reader, DIRECT_FRAME_SIZE);
            let mut challenge = [0; 37];
            io.read_exact(&mut challenge).await?;
            assert_eq!(&challenge[..5], &[0,0,0,0,1]);
            if name == "test" {
                io.write_all(&[0;32]).await?; // Deliberately wrong credentials.
                io.flush().await?;
            }
            let mut answer = [0;4];
            io.read_exact(&mut answer).await?;
            assert_eq!(u32::from_le_bytes(answer), ack);
        }
        let mut tcp = TcpStream::connect(address).await?;
        tcp.write_all(b"GET /api/tunnel HTTP/1.1\r\nHost: localhost\r\nUpgrade: porthub.tcp.v1\r\nConnection: close\r\n\r\n").await?;
        let mut response = String::new();
        BufReader::new(tcp).read_line(&mut response).await?;
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
        server.write().await.shutdown().await;
        serving.abort();
        Ok::<_, anyhow::Error>(())
    }).await??;
    Ok(())
}
