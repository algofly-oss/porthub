use anyhow::{ensure, Result};
use porthub_runtime::gateway_apply;
use porthub_tunnel::{gateway_config, EmbeddedServer};
use std::sync::Arc;
use tokio::{
    net::{TcpListener, UnixListener},
    sync::RwLock,
};

#[tokio::test]
async fn apply_requires_exact_valid_file_digest_and_is_not_publicly_routed() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("gateway.toml");
    let original = "[server.services]\n";
    std::fs::write(&path, original)?;
    let server = Arc::new(RwLock::new(
        EmbeddedServer::new(gateway_config(original)?).await?,
    ));
    let socket = temporary.path().join("edge.sock");
    let listener = UnixListener::bind(&socket)?;
    let control = porthub_edge::apply::router(server.clone(), path.clone());
    let task = tokio::spawn(async move { axum::serve(listener, control).await });
    let public = TcpListener::bind("127.0.0.1:0").await?;
    let address = public.local_addr()?;
    let router = porthub_edge::router(server.clone());
    let public_task = tokio::spawn(async move { axum::serve(public, router).await });
    let result=async {
        let client=reqwest::Client::builder().unix_socket(socket).no_proxy().build()?;
        let cases=[
            (serde_json::json!({"digest":"0".repeat(64)}),409),
            (serde_json::json!({"digest":"nope"}),400),
            (serde_json::json!({"digest":gateway_apply::digest(original.as_bytes()),"extra":true}),422),
            (serde_json::json!({"digest":gateway_apply::digest(original.as_bytes())}),200),
        ];
        for (body,status) in cases {
            let response=client.post("http://localhost/apply").header("content-type","application/json").body(body.to_string()).send().await?;
            ensure!(response.status().as_u16()==status,"unexpected apply response: {}",response.status());
            if status==200 {
                let response:gateway_apply::Snapshot=serde_json::from_slice(&response.bytes().await?)?;
                ensure!(response.digest==gateway_apply::digest(original.as_bytes()));
            }
        }
        std::fs::write(&path,"not valid TOML = [")?;
        let invalid=std::fs::read(&path)?;
        let response=client.post("http://localhost/apply").header("content-type","application/json")
            .body(serde_json::json!({"digest":gateway_apply::digest(&invalid)}).to_string()).send().await?;
        ensure!(response.status()==409);
        let response=reqwest::Client::new().post(format!("http://{address}/apply")).body("{}").send().await?;
        ensure!(response.status()==404,"control endpoint leaked to public ingress");
        Ok(())
    }.await;
    task.abort();
    public_task.abort();
    server.write().await.shutdown().await;
    result
}
