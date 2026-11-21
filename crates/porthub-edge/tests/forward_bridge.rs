//! Real public TCP clients traverse the role-scoped control socket. The public
//! HTTP router never serves the management endpoints.
use anyhow::{ensure, Result};
use porthub_tunnel::{gateway_config, EmbeddedServer};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixListener},
    sync::RwLock,
};
#[tokio::test]
async fn public_listener_requires_exact_entry_can_half_close_and_releases_port_on_delete(
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(8), async {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("edge.sock");
        let internal = UnixListener::bind(&path)?;
        let server = Arc::new(RwLock::new(
            EmbeddedServer::new(gateway_config("[server.services]")?).await?,
        ));
        let api = porthub_edge::apply::router(server.clone(), tmp.path().join("config"));
        let serving = tokio::spawn(async move { axum::serve(internal, api).await });
        let public = TcpListener::bind("127.0.0.1:0").await?;
        let public_address = public.local_addr()?;
        let ingress =
            tokio::spawn(async move { axum::serve(public, porthub_edge::router(server)).await });
        let edge = reqwest::Client::builder().unix_socket(path).build()?;
        let id = "aaaaaaaaaaaaaaaaaaaaaaaa";
        let other = "bbbbbbbbbbbbbbbbbbbbbbbb";
        let port = TcpListener::bind("127.0.0.1:0").await?.local_addr()?.port();
        let url = format!("http://localhost/forwards/public/{id}/{port}");
        ensure!(
            reqwest::get(format!("http://{public_address}/forwards/public"))
                .await?
                .status()
                == 404
        );
        ensure!(edge.post(&url).send().await?.status() == 204);
        ensure!(edge.post(url.replace(id, other)).send().await?.status() == 409);
        ensure!(
            edge.post(format!("{}/accept", url.replace(id, other)))
                .send()
                .await?
                .status()
                == 404
        );
        let mut client = TcpStream::connect(("127.0.0.1", port)).await?;
        let response = edge
            .post(format!("{url}/accept"))
            .header("connection", "Upgrade")
            .header("upgrade", "porthub-forward-v1")
            .send()
            .await?;
        ensure!(response.status() == 101);
        let mut bridge = response.upgrade().await?;
        client.write_all(b"hello").await?;
        client.shutdown().await?;
        let mut text = Vec::new();
        bridge.read_to_end(&mut text).await?;
        ensure!(text == b"hello");
        bridge.write_all(b"reply").await?;
        bridge.shutdown().await?;
        text.clear();
        client.read_to_end(&mut text).await?;
        ensure!(text == b"reply");
        ensure!(
            edge.delete(format!("http://localhost/forwards/public/{other}"))
                .send()
                .await?
                .status()
                == 204
        );
        ensure!(
            edge.delete(format!("http://localhost/forwards/public/{id}"))
                .send()
                .await?
                .status()
                == 204
        );
        ensure!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
        serving.abort();
        ingress.abort();
        Ok(())
    })
    .await?
}
