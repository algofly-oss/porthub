//! Full agent runtimes, native API, Mongo, and two exits in disposable containers.
use anyhow::{ensure, Context, Result};
use mongodb::bson::{doc, oid::ObjectId};
use porthub_api::{config::Config, domain::workspaces::token_digest};
use serde_json::json;
use std::time::Duration;
use tokio::{io::{AsyncBufReadExt, AsyncWriteExt, BufReader}, net::TcpListener};
use tokio_util::sync::CancellationToken;
mod support;
use support::Case;

async fn docker(args: Vec<String>) -> Result<String> {
    let logs = args.first().is_some_and(|value| value == "logs");
    let output = tokio::process::Command::new("docker").args(args).output().await?;
    ensure!(output.status.success(), "docker operation failed: {}", String::from_utf8_lossy(&output.stderr));
    if logs { return Ok(format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr))); }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
fn args(values: &[&str]) -> Vec<String> { values.iter().map(|value| (*value).to_owned()).collect() }

#[tokio::test]
#[ignore = "run through scripts/verify-exit-network.py with isolated Docker networks"]
async fn native_agents_use_two_exits_and_preserve_established_tcp() -> Result<()> {
    let network = std::env::var("PORTHUB_TEST_CONTROL_NETWORK")?;
    let external = std::env::var("PORTHUB_TEST_EXTERNAL_NETWORK")?;
    ensure!(network.starts_with("porthub-exit-test-") && external.starts_with("porthub-exit-test-"), "requires owned test networks");
    let binary = std::env::var("PORTHUB_TEST_WORKER_BINARY")?;
    let listener = TcpListener::bind("198.18.10.1:0").await?;
    let base = format!("http://{}", listener.local_addr()?);
    let case = Case::new(Config {
        gateway_advertised_url: Some(base.clone()),
        public_base_url: base.clone(),
        private_transport: porthub_api::private_transport::Settings::parse("[]", "", "exit-network-test-relay-secret-0123456789abcdef"),
        ..Default::default()
    }).await?;
    let api = tokio::spawn(axum::serve(listener, case.router.clone()).into_future());
    let cancel = CancellationToken::new();
    let mut containers: Vec<String> = Vec::new();
    let target_listener = TcpListener::bind("203.0.113.1:0").await?;
    let target = target_listener.local_addr()?.to_string();
    let udp_listener = tokio::net::UdpSocket::bind(&target).await?;
    let udp_cancel = cancel.clone();
    let udp_server = tokio::spawn(async move {
        let mut buffer = [0u8; 256];
        loop {
            let (_, peer) = tokio::select! { _ = udp_cancel.cancelled() => break, result = udp_listener.recv_from(&mut buffer) => result? };
            udp_listener.send_to(peer.ip().to_string().as_bytes(), peer).await?;
        }
        Ok::<_, anyhow::Error>(())
    });
    let control_listener = TcpListener::bind("198.18.10.1:0").await?;
    let control_target = control_listener.local_addr()?.to_string();
    let (owner, _) = case.user("exit-network@example.invalid", "user").await?;
    let ids = [ObjectId::new(), ObjectId::new(), ObjectId::new()];
    let exit_id = ObjectId::new();
    let app = case.app.clone();
    let stopped = cancel.clone();
    let test_network = network.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, peer) = tokio::select! { _ = stopped.cancelled() => break, value = target_listener.accept() => value?, value = control_listener.accept() => value? };
            let app = app.clone(); let stopped = stopped.clone(); let test_network = test_network.clone();
            tokio::spawn(async move {
                stream.write_all(format!("{}\n", peer.ip()).as_bytes()).await?;
                let mut stream = BufReader::new(stream);
                loop {
                    let mut line = String::new();
                    let size = tokio::select! { _ = stopped.cancelled() => break, size = stream.read_line(&mut line) => size? };
                    if size == 0 {
                        // The client closed its write half; its read half must
                        // still receive the server's final response through the exit.
                        stream.get_mut().write_all(format!("{}\n", peer.ip()).as_bytes()).await?;
                        stream.get_mut().shutdown().await?;
                        break;
                    }
                    let response = if let Some(mode) = line.trim().strip_prefix("mode:") {
                        ensure!(["round_robin", "sticky", "random"].contains(&mode), "invalid test mode");
                        app.collection("private_exit_nodes").update_one(doc! {"_id":exit_id}, doc! {"$set":{"selection":mode}}).await?;
                        "updated\n".to_owned()
                    } else if let Some(value) = line.trim().strip_prefix("fallback:") {
                        ensure!(["on", "off"].contains(&value), "invalid fallback fixture command");
                        app.collection("private_exit_nodes").update_one(doc! {"_id":exit_id}, doc! {"$set":{"allow_direct_fallback":value == "on"}}).await?;
                        "updated\n".to_owned()
                    } else if let Some(action) = line.trim().strip_prefix("exits:") {
                        ensure!(["start", "stop"].contains(&action), "invalid exit fixture command");
                        for node in [1, 2] {
                            let name = format!("{test_network}-node-{node}");
                            if action == "stop" { docker(args(&["stop", "--time", "5", &name])).await?; }
                            else { docker(args(&["start", &name])).await?; }
                        }
                        "updated\n".to_owned()
                    } else if let Some(ip) = line.trim().strip_prefix("offline:") {
                        let node = match ip { "203.0.113.2" => 1, "203.0.113.3" => 2, _ => anyhow::bail!("invalid test exit") };
                        docker(args(&["stop", "--time", "5", &format!("{test_network}-node-{node}")])).await?;
                        "updated\n".to_owned()
                    } else { format!("{}\n", peer.ip()) };
                    stream.get_mut().write_all(response.as_bytes()).await?;
                }
                Ok::<_, anyhow::Error>(())
            });
        }
        Ok::<_, anyhow::Error>(())
    });
    let result = async {
        let token = "exit-network-fixture-token-0123456789abcdef";
        for (i, machine) in ids.iter().enumerate() {
            case.app.collection("machines").insert_one(doc! {"_id":machine,"user_id":owner,"name":format!("exit-test-{i}"),"token":"unified-public-fixture-token"}).await?;
            case.app.collection("private_peers").insert_one(doc! {"_id":format!("{owner}:{machine}"),"workspace_id":owner,"machine_id":machine,"owner_id":owner,
                "ip":format!("10.234.240.{}",i+10),"enabled":true,"credential_hash":token_digest(token)}).await?;
        }
        case.app.collection("private_exit_nodes").insert_one(doc! {"_id":exit_id,"workspace_id":owner,"name":"Two exits","enabled":true,"selection":"round_robin",
            "routing_selectors":[{"kind":"machine","id":ids[1].to_hex()},{"kind":"machine","id":ids[2].to_hex()}],
            "distribution_selectors":[{"kind":"machine","id":ids[0].to_hex()}]}).await?;
        for i in [1usize, 2, 0] {
            let name = format!("{network}-node-{i}");
            containers.push(name.clone());
            let profile = json!({"server":base,"workspace":owner.to_hex(),"peer_id":format!("{owner}:{}",ids[i]),"token":token,"allow_insecure_http_for_tests":true}).to_string();
            let ip = format!("198.18.10.{}", i + 2);
            let mount = format!("type=bind,src={binary},dst=/worker,readonly");
            let env_profile = format!("PORTHUB_TEST_PROFILE={profile}");
            let env_role = format!("PORTHUB_TEST_ROLE={}", if i == 0 { "consumer" } else { "exit" });
            let env_target = format!("PORTHUB_TEST_TARGET={target}");
            let env_control = format!("PORTHUB_TEST_CONTROL_TARGET={control_target}");
            let public_profile = json!({"server":base,"machine_id":ids[i].to_hex(),"token":"unified-public-fixture-token","allow_insecure_http_for_tests":true}).to_string();
            let env_public = format!("PORTHUB_TEST_PUBLIC_PROFILE={public_profile}");
            docker(args(&["create", "--name", &name, "--network", &network, "--ip", &ip, "--read-only",
                "--tmpfs", "/state:rw,mode=700", "--tmpfs", "/run/porthub-exits:rw,mode=700", "--tmpfs", "/tmp:rw,mode=1777",
                "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "--security-opt", "no-new-privileges:true", "--security-opt", "systempaths=unconfined",
                "--security-opt", "apparmor=unconfined", "--sysctl", "net.ipv4.ip_forward=0", "--device", "/dev/net/tun",
                "--env", "PORTHUB_TEST_OWNED_NETNS=1", "--env", &env_profile, "--env", &env_public, "--env", &env_role, "--env", &env_target, "--env", &env_control,
                "--mount", &mount, "--entrypoint", "/worker", "porthub:edge", "--ignored", "--exact", "isolated_exit_worker", "--nocapture"])).await?;
            if i > 0 { docker(args(&["network", "connect", "--ip", &format!("203.0.113.{}",i+1), &external, &name])).await?; }
            docker(args(&["start", &name])).await?;
        }
        let consumer = containers.last().unwrap();
        let status = tokio::time::timeout(Duration::from_secs(180), docker(args(&["wait", consumer]))).await.context("exit consumer timed out")??;
        let logs = docker(args(&["logs", consumer])).await?;
        println!("{logs}");
        ensure!(status == "0", "exit consumer failed with status {status}");
        Ok::<_, anyhow::Error>(())
    }.await;
    for name in &containers {
        if result.is_err() { if let Ok(logs) = docker(args(&["logs", name])).await { eprintln!("{name}: {logs}"); } }
        let _ = docker(args(&["stop", "--time", "5", name])).await;
        let _ = docker(args(&["rm", "-f", name])).await;
    }
    cancel.cancel(); api.abort(); let _ = server.await; let _ = udp_server.await; case.db.drop().await?;
    result
}
use std::future::IntoFuture;
