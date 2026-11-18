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
    // Consumer wait retains its original 180s functional bound; metadata and
    // cleanup commands are individually capped at30s.
    let seconds=if args.first().is_some_and(|value|value=="wait"){180}else{30};
    let output = tokio::time::timeout(Duration::from_secs(seconds),tokio::process::Command::new("docker").args(args).kill_on_drop(true).output()).await.context("owned Docker command timed out")??;
    ensure!(output.status.success(), "docker operation failed: {}", String::from_utf8_lossy(&output.stderr));
    if logs { return Ok(format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr))); }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
fn args(values: &[&str]) -> Vec<String> { values.iter().map(|value| (*value).to_owned()).collect() }

#[tokio::test]
#[ignore = "run through scripts/verify-exit-network.py with isolated Docker networks"]
async fn native_agents_use_two_exits_and_preserve_established_tcp() -> Result<()> {
    run_network_fixture(false).await
}
#[tokio::test]
#[ignore = "run through scripts/verify-exit-network.py --sparse --scenario peers"]
async fn native_agents_negotiate_quic3_and_transfer_owned_tcp() -> Result<()> {
    ensure!(cfg!(feature="private-sparse"),"paired quic3 fixture requires sparse build");
    run_network_fixture(true).await
}
async fn run_network_fixture(paired:bool)->Result<()> {
    let network = std::env::var("PORTHUB_TEST_CONTROL_NETWORK")?;
    let external = std::env::var("PORTHUB_TEST_EXTERNAL_NETWORK")?;
    ensure!(network.starts_with("porthub-exit-test-") && external.starts_with("porthub-exit-test-"), "requires owned test networks");
    let binary = std::env::var("PORTHUB_TEST_WORKER_BINARY")?;
    let image = std::env::var("PORTHUB_TEST_WORKER_IMAGE")?;
    ensure!(image.starts_with("sha256:")&&image.len()==71&&image[7..].bytes().all(|b|b.is_ascii_hexdigit()&&!b.is_ascii_uppercase()),"immutable local fixture image required");
    let runtime_root=std::env::var("PORTHUB_TEST_RUNTIME_ROOT")?;
    let runtime_loader=std::env::var("PORTHUB_TEST_RUNTIME_LOADER")?;
    ensure!(runtime_root.starts_with("/tmp/porthub-exit-runtime-")&&runtime_root.ends_with("/lib")&&!runtime_loader.contains(['/', '\\'])&&runtime_loader.starts_with("ld-"),"owned matching runtime required");
    let nonce=std::env::var("PORTHUB_TEST_FIXTURE_NONCE")?;
    ensure!(network==format!("{nonce}-control")&&external==format!("{nonce}-external"),"fixture networks not nonce-bound");
    let listener = TcpListener::bind("198.18.10.1:0").await?;
    let base = format!("http://{}", listener.local_addr()?);
    // Finish fallible host listener setup before starting any task or Case DB.
    let target_listener = TcpListener::bind("203.0.113.1:0").await?;
    let target = target_listener.local_addr()?.to_string();
    let udp_listener = tokio::net::UdpSocket::bind(&target).await?;
    let control_listener = TcpListener::bind("198.18.10.1:0").await?;
    let control_target = control_listener.local_addr()?.to_string();
    let case = Case::new(Config {
        gateway_advertised_url: Some(base.clone()), public_base_url: base.clone(),
        private_transport: porthub_api::private_transport::Settings::parse("[]", "", "exit-network-test-relay-secret-0123456789abcdef"),
        ..Default::default()
    }).await?;
    let owner=match case.user("exit-network@example.invalid", "user").await {
        Ok((owner,_))=>owner,Err(error)=>{case.db.drop().await?;return Err(error);}
    };
    let api = tokio::spawn(axum::serve(listener, case.router.clone()).into_future());
    let cancel = CancellationToken::new();
    let mut containers: Vec<String> = Vec::new();
    let udp_cancel = cancel.clone();
    let udp_server = tokio::spawn(async move {
        let mut buffer = [0u8; 256];
        let mut diagnostic_count=0usize;
        loop {
            let (_, peer) = tokio::select! { _ = udp_cancel.cancelled() => break, result = udp_listener.recv_from(&mut buffer) => result? };
            if diagnostic_count<8 {eprintln!("native_fixture_udp_server_received=true");diagnostic_count+=1;}
            udp_listener.send_to(peer.ip().to_string().as_bytes(), peer).await?;
        }
        Ok::<_, anyhow::Error>(())
    });
    let ids:Vec<_>=(0..if paired{2}else{3}).map(|_|ObjectId::new()).collect();
    let exit_id = ObjectId::new();
    let app = case.app.clone();
    let stopped = cancel.clone();
    let test_network = network.clone();
    let peer_complete=std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let server = tokio::spawn(async move {
        let mut connections=tokio::task::JoinSet::new();
        loop {
            let (mut stream, peer) = tokio::select! { _ = stopped.cancelled() => break, value = target_listener.accept() => value?, value = control_listener.accept() => value? };
            let app = app.clone(); let stopped = stopped.clone(); let test_network = test_network.clone();let peer_complete=peer_complete.clone();
            connections.spawn(async move {
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
                    let response = if line.trim()=="native:consumer-complete" {
                        peer_complete.store(true,std::sync::atomic::Ordering::SeqCst);"updated\n".to_owned()
                    } else if line.trim()=="native:consumer-done?" {
                        if peer_complete.load(std::sync::atomic::Ordering::SeqCst){"ready\n".to_owned()}else{"waiting\n".to_owned()}
                    } else if line.trim()=="quic3:ready" {
                        let count=app.collection("private_peers").count_documents(doc!{"workspace_id":owner,"stream_transport":"quic3-credit"}).await?;
                        if count==2{"ready\n".to_owned()}else{"waiting\n".to_owned()}
                    } else if let Some(mode) = line.trim().strip_prefix("mode:") {
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
        connections.abort_all();while connections.join_next().await.is_some(){}
        Ok::<_, anyhow::Error>(())
    });
    let result = async {
        let token = "exit-network-fixture-token-0123456789abcdef";
        for (i, machine) in ids.iter().enumerate() {
            case.app.collection("machines").insert_one(doc! {"_id":machine,"user_id":owner,"name":format!("exit-test-{i}"),"token":"unified-public-fixture-token"}).await?;
            case.app.collection("private_peers").insert_one(doc! {"_id":format!("{owner}:{machine}"),"workspace_id":owner,"machine_id":machine,"owner_id":owner,
                "ip":format!("10.234.240.{}",i+10),"enabled":true,"credential_hash":token_digest(token)}).await?;
        }
        if cfg!(feature="private-sparse") {
            case.app.collection("private_networks").insert_one(doc!{"_id":owner.to_hex(),"cidr":"10.234.224.0/19","dns_suffix":"phub"}).await?;
        }
        if paired {
            let group=ObjectId::new();let book=ObjectId::new();
            case.app.collection("machine_groups").insert_one(doc!{"_id":group,"user_id":owner}).await?;
            case.app.collection("access_rulebooks").insert_one(doc!{"_id":book,"user_id":owner,"group_id":group.to_hex(),"revision":1_i64,"enabled":true,
                "rules":[{"id":"native443","name":"Owned paired native stream","sources":[{"kind":"all","id":"machines"}],"destinations":[{"kind":"all","id":"machines"}],"protocol":"tcp","ports":"443","bidirectional":true,"enabled":true}]}).await?;
        } else {case.app.collection("private_exit_nodes").insert_one(doc! {"_id":exit_id,"workspace_id":owner,"name":"Two exits","enabled":true,"selection":"round_robin",
            "routing_selectors":[{"kind":"machine","id":ids[1].to_hex()},{"kind":"machine","id":ids[2].to_hex()}],
            "distribution_selectors":[{"kind":"machine","id":ids[0].to_hex()}]}).await?;}
        let order:Vec<usize>=if paired{vec![1,0]}else{vec![1,2,0]};
        for i in order {
            let name = format!("{network}-node-{i}");

            let profile = json!({"server":base,"workspace":owner.to_hex(),"peer_id":format!("{owner}:{}",ids[i]),"token":token,"allow_insecure_http_for_tests":true}).to_string();
            let ip = format!("198.18.10.{}", i + 2);
            let mount = format!("type=bind,src={binary},dst=/worker,readonly");
            let runtime_mount=format!("type=bind,src={runtime_root},dst=/fixture-runtime,readonly");
            let entrypoint=format!("/fixture-runtime/{runtime_loader}");
            let env_profile = format!("PORTHUB_TEST_PROFILE={profile}");
            let env_role = format!("PORTHUB_TEST_ROLE={}", if paired{if i==0{"private-consumer"}else{"private-provider"}}else if i==0{"consumer"}else{"exit"});
            let env_peer_target="PORTHUB_TEST_PEER_TARGET=10.234.240.11:443";
            let label=format!("porthub.exit_fixture={nonce}");
            let env_nonce=format!("PORTHUB_TEST_FIXTURE_NONCE={nonce}");
            let env_target = format!("PORTHUB_TEST_TARGET={target}");
            let env_control = format!("PORTHUB_TEST_CONTROL_TARGET={control_target}");
            let public_profile = json!({"server":base,"machine_id":ids[i].to_hex(),"token":"unified-public-fixture-token","allow_insecure_http_for_tests":true}).to_string();
            let env_public = format!("PORTHUB_TEST_PUBLIC_PROFILE={public_profile}");
            docker(args(&["create", "--pull=never", "--name", &name, "--network", &network, "--ip", &ip, "--read-only",
                "--label", &label, "--memory", "768m", "--cpus", "1", "--pids-limit", "256",
                "--tmpfs", "/state:rw,mode=700,size=16m", "--tmpfs", "/run/porthub-exits:rw,mode=700,size=8m", "--tmpfs", "/tmp:rw,mode=1777,size=64m",
                "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "--security-opt", "no-new-privileges:true", "--security-opt", "systempaths=unconfined",
                "--security-opt", "apparmor=unconfined", "--sysctl", "net.ipv4.ip_forward=0", "--device", "/dev/net/tun",
                "--env", "PORTHUB_TEST_OWNED_NETNS=1", "--env", &env_profile, "--env", &env_public, "--env", &env_role, "--env", &env_target, "--env", &env_control, "--env", env_peer_target, "--env", &env_nonce,
                "--mount", &mount, "--mount", &runtime_mount, "--entrypoint", &entrypoint, &image, "--library-path", "/fixture-runtime", "/worker", "--ignored", "--exact", "isolated_exit_worker", "--nocapture"])).await?;
            containers.push(name.clone());
            if i > 0 && !paired { docker(args(&["network", "connect", "--ip", &format!("203.0.113.{}",i+1), &external, &name])).await?; }
            docker(args(&["start", &name])).await?;
        }
        let consumer = containers.last().unwrap();
        let status = tokio::time::timeout(Duration::from_secs(180), docker(args(&["wait", consumer]))).await.context("exit consumer timed out")??;
        let logs = docker(args(&["logs", consumer])).await?;
        println!("{logs}");
        ensure!(status == "0", "exit consumer failed with status {status}");
        if paired {
            let provider=containers.first().context("native provider absent")?;
            let status=tokio::time::timeout(Duration::from_secs(10),docker(args(&["wait",provider]))).await.context("native provider did not finish after consumer verification")??;
            println!("{}",docker(args(&["logs",provider])).await?);
            ensure!(status=="0","native provider failed guarded payload verification: {status}");
            ensure!(case.app.collection("private_peers").count_documents(doc!{"workspace_id":owner,"stream_transport":"quic3-credit"}).await?==2,"both native agents did not negotiate quic3-credit");
            println!("actual_two_agent_quic3_negotiation=true synthetic_transport=false");
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    if result.is_err() {
        for (slot,machine) in ids.iter().enumerate() {
            match tokio::time::timeout(Duration::from_secs(2),case.app.collection("private_peers").find_one(doc!{"_id":format!("{owner}:{machine}")})).await {
                Ok(Ok(Some(peer)))=>{
                    let transport=peer.get_str("stream_transport").ok().filter(|value|["none","quic1","quic2","quic3-credit"].contains(value)).unwrap_or("other");
                    let age=peer.get_datetime("last_seen_at").ok().map(|seen|(mongodb::bson::DateTime::now().timestamp_millis()-seen.timestamp_millis()).max(0));
                    println!("native_fixture_peer slot={slot} transport={transport} fingerprint_present={} instance_present={} enabled={} last_seen_age_ms={age:?} exit_ready={}",peer.get_str("fingerprint").is_ok_and(|s|!s.is_empty()),peer.get_str("instance").is_ok_and(|s|!s.is_empty()),peer.get_bool("enabled").unwrap_or(false),peer.get_bool("exit_ready").unwrap_or(false));
                },_=>println!("native_fixture_peer slot={slot} metadata=unavailable"),
            }
        }
    }
    let mut cleanup_errors=Vec::new();
    for name in &containers {
        if result.is_err() { if let Ok(logs) = docker(args(&["logs", name])).await { eprintln!("{name}: {logs}"); } }
        let inspected=docker(args(&["inspect",name])).await;
        let owned=inspected.as_ref().ok().and_then(|value|serde_json::from_str::<serde_json::Value>(value).ok()).and_then(|value|value.as_array().and_then(|v|v.first()).cloned())
            .is_some_and(|value|value["Config"]["Labels"]["porthub.exit_fixture"].as_str()==Some(&nonce)&&value["Image"].as_str()==Some(&image));
        if !owned {cleanup_errors.push("container-identity");continue;}
        let _ = docker(args(&["stop", "--time", "5", name])).await;
        if docker(args(&["rm", "-f", name])).await.is_err(){cleanup_errors.push("container-remove");}
    }
    match docker(args(&["ps","-aq","--filter",&format!("label=porthub.exit_fixture={nonce}")])).await {
        Ok(remaining) if remaining.is_empty()=>{},_=>cleanup_errors.push("owned-container-remains"),
    }
    cancel.cancel(); api.abort();let api_join=api.await;
    if !api_join.is_err_and(|error|error.is_cancelled()){cleanup_errors.push("api-reap");}
    if !matches!(server.await,Ok(Ok(()))){cleanup_errors.push("fixture-server-reap");}
    if !matches!(udp_server.await,Ok(Ok(()))){cleanup_errors.push("fixture-udp-reap");}
    if case.db.drop().await.is_err(){cleanup_errors.push("case-db-drop");}
    println!("owned_native_fixture_cleanup={} scenario={}",cleanup_errors.is_empty(),if paired{"peers"}else{"exits"});
    if !cleanup_errors.is_empty(){return Err(result.err().unwrap_or_else(||anyhow::anyhow!("native fixture cleanup failed")).context(format!("fixture cleanup categories: {cleanup_errors:?}")));}
    result
}
use std::future::IntoFuture;
