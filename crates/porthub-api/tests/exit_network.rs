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
    run_network_fixture(false,false,false).await
}
#[tokio::test]
#[ignore = "run through scripts/verify-exit-network.py --sparse --scenario peers"]
async fn native_agents_negotiate_quic3_and_transfer_owned_tcp() -> Result<()> {
    ensure!(cfg!(feature="private-sparse"),"paired quic3 fixture requires sparse build");
    run_network_fixture(true,false,false).await
}
#[tokio::test]
#[ignore="owned fault-injected relay first-packet gate; use reviewed netns wrapper"]
async fn native_relay_exit_first_udp_waits_for_pair_and_native_ack()->Result<()>{run_network_fixture(false,true,false).await}
#[tokio::test]
#[ignore="actual collision/API worker/native reopen; reviewed existing Docker wrapper only"]
async fn native_agents_report_collision_renumber_and_reopen_allowed_private_ip()->Result<()>{
    ensure!(cfg!(feature="private-sparse"),"native renumber requires sparse build");
    run_network_fixture(true,false,true).await
}
async fn run_network_fixture(paired:bool,gated:bool,renumber:bool)->Result<()> {
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
    let ids:Vec<_>=(0..if paired{2}else{3}).map(|_|ObjectId::new()).collect();
    let repair_seen=std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let router=if renumber {
        let observed=repair_seen.clone();let report_source=format!("{owner}:{}",ids[0]);
        case.router.clone().layer(axum::middleware::from_fn(move |request:axum::http::Request<axum::body::Body>,next:axum::middleware::Next|{
            let observed=observed.clone();let report_source=report_source.clone();async move {
                if request.method()!=axum::http::Method::POST||request.uri().path()!="/api/access/private/sync"{return Ok::<_,axum::http::StatusCode>(next.run(request).await);}
                let(parts,body)=request.into_parts();let bytes=axum::body::to_bytes(body,65536).await.map_err(|_|axum::http::StatusCode::PAYLOAD_TOO_LARGE)?;
                let value=serde_json::from_slice::<serde_json::Value>(&bytes).ok();
                let report=value.as_ref().filter(|v|v["peer_id"].as_str()==Some(report_source.as_str())).and_then(|v|serde_json::from_value::<porthub_network::native_repair::Request>(v["native_repair"].clone()).ok());
                let matched=report.is_some_and(|r|r.validate().is_ok()&&r.source==std::net::Ipv4Addr::new(10,234,240,10)&&r.blocked.iter().any(|p|p.to_string()=="10.234.224.0/19"));
                let response=next.run(axum::http::Request::from_parts(parts,axum::body::Body::from(bytes))).await;
                // Observe only a genuine network request accepted by the real
                // authenticated route. No test report/queue/ACK is published.
                if matched&&response.status().is_success(){observed.store(true,std::sync::atomic::Ordering::SeqCst);}
                Ok::<_,axum::http::StatusCode>(response)
            }
        }))
    }else{case.router.clone()};
    let api = tokio::spawn(axum::serve(listener, router).into_future());
    let cancel = CancellationToken::new();
    let (recovery_stop,recovery_stopping)=tokio::sync::watch::channel(false);
    let recovery=renumber.then(||tokio::spawn(porthub_api::private_renumber::worker::run(case.app.clone(),recovery_stopping)));
    let mut containers: Vec<String> = Vec::new();
    let udp_cancel = cancel.clone();
    let udp_received=std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));let udp_count=udp_received.clone();let expected_udp=format!("relay-origin-first-{nonce}");
    let udp_server = tokio::spawn(async move {
        let mut buffer = [0u8; 256];
        let mut diagnostic_count=0usize;
        loop {
            let (size, peer) = tokio::select! { _ = udp_cancel.cancelled() => break, result = udp_listener.recv_from(&mut buffer) => result? };
            if diagnostic_count<8 {eprintln!("native_fixture_udp_server_received=true");diagnostic_count+=1;}
            if gated {
                ensure!(peer.ip()=="203.0.113.2".parse::<std::net::IpAddr>()?&&&buffer[..size]==expected_udp.as_bytes(),"owned relay UDP source/payload differed");
                udp_count.fetch_add(1,std::sync::atomic::Ordering::SeqCst);udp_listener.send_to(&buffer[..size],peer).await?;
            }else{udp_listener.send_to(peer.ip().to_string().as_bytes(), peer).await?;}
        }
        Ok::<_, anyhow::Error>(())
    });
    let control_ids=ids.clone();
    let exit_id = ObjectId::new();
    let app = case.app.clone();
    let stopped = cancel.clone();
    let test_network = network.clone();
    let peer_complete=std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let server = tokio::spawn(async move {
        let mut connections=tokio::task::JoinSet::new();
        loop {
            let (mut stream, peer) = tokio::select! { _ = stopped.cancelled() => break, value = target_listener.accept() => value?, value = control_listener.accept() => value? };
            let app = app.clone(); let stopped = stopped.clone(); let test_network = test_network.clone();let peer_complete=peer_complete.clone();let control_ids=control_ids.clone();let repair_seen=repair_seen.clone();
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
                    let response = if renumber&&line.trim()=="renumber:state" {
                        let own_id=format!("{owner}:{}",control_ids[0]);let target_id=format!("{owner}:{}",control_ids[1]);
                        let own=app.collection("private_peers").find_one(doc!{"_id":&own_id}).await?.context("owned renumber source missing")?;
                        let target=app.collection("private_peers").find_one(doc!{"_id":&target_id}).await?.context("owned renumber target missing")?;
                        let head=app.collection("private_renumber_heads").find_one(doc!{"_id":owner.to_hex()}).await?;
                        let retained=app.collection("private_retired_sources").count_documents(doc!{"workspace":owner.to_hex(),"activated":true}).await?>0;
                        format!("{}\n",json!({"source":own.get_str("ip")?,"target":target.get_str("ip")?,"source_instance":own.get_str("instance").unwrap_or(""),"target_instance":target.get_str("instance").unwrap_or(""),"ready":own.get_str("stream_transport").ok()==Some("quic3-credit")&&target.get_str("stream_transport").ok()==Some("quic3-credit"),"generation":head.as_ref().and_then(|h|h.get_i64("generation").ok()).unwrap_or(0),"stable":head.as_ref().is_some_and(|h|h.get_str("state").ok()==Some("stable")),"report_observed":repair_seen.load(std::sync::atomic::Ordering::SeqCst),"retained":retained}))
                    } else if line.trim()=="native:consumer-complete" {
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
            if renumber{case.app.collection("private_peers").update_one(doc!{"_id":format!("{owner}:{machine}")},doc!{"$set":{"enrollment_generation":"owned-native-renumber-v1","custom_hostname":format!("stable-{i}.phub")}}).await?;}
        }
        if cfg!(feature="private-sparse") {
            case.app.collection("private_networks").insert_one(doc!{"_id":owner.to_hex(),"cidr":"10.234.224.0/19","dns_suffix":"phub"}).await?;
            if renumber{case.app.collection("private_networks").update_one(doc!{"_id":owner.to_hex()},doc!{"$set":{"native_fixture_preference":"preserved"}}).await?;}
        }
        if gated {
            let group=ObjectId::new();let book=ObjectId::new();
            case.app.collection("machine_groups").insert_one(doc!{"_id":group,"user_id":owner}).await?;
            case.app.collection("access_rulebooks").insert_one(doc!{"_id":book,"user_id":owner,"group_id":group.to_hex(),"revision":1_i64,"enabled":true,
                "rules":[{"id":"relay-bootstrap443","name":"Owned unrelated private bootstrap","sources":[{"kind":"machine","id":ids[0].to_hex()},{"kind":"machine","id":ids[1].to_hex()}],"destinations":[{"kind":"machine","id":ids[2].to_hex()}],"protocol":"tcp","ports":"443","bidirectional":true,"enabled":true}]}).await?;
        }
        if paired {
            let group=ObjectId::new();let book=ObjectId::new();
            case.app.collection("machine_groups").insert_one(doc!{"_id":group,"user_id":owner}).await?;
            case.app.collection("access_rulebooks").insert_one(doc!{"_id":book,"user_id":owner,"group_id":group.to_hex(),"revision":1_i64,"enabled":true,
                "rules":[{"id":"native443","name":"Owned paired native stream","sources":[{"kind":"all","id":"machines"}],"destinations":[{"kind":"all","id":"machines"}],"protocol":"tcp","ports":"443","bidirectional":true,"enabled":true}]}).await?;
            if renumber{case.app.collection("access_rulebooks").update_one(doc!{"_id":book},doc!{"$push":{"rules":{"id":"native-udp443","name":"Owned renumber UDP","sources":[{"kind":"all","id":"machines"}],"destinations":[{"kind":"all","id":"machines"}],"protocol":"udp","ports":"443","bidirectional":true,"enabled":true}}}).await?;}
        } else {case.app.collection("private_exit_nodes").insert_one(doc! {"_id":exit_id,"workspace_id":owner,"name":"Two exits","enabled":true,"selection":"round_robin",
            "routing_selectors":ids.iter().skip(1).take(if gated{1}else{2}).map(|id|doc!{"kind":"machine","id":id.to_hex()}).collect::<Vec<_>>(),
            "distribution_selectors":[{"kind":"machine","id":ids[0].to_hex()}]}).await?;}
        let identity_projection=doc!{"_id":1,"workspace_id":1,"machine_id":1,"owner_id":1,"enabled":1,"credential_hash":1,"enrollment_generation":1,"custom_hostname":1};
        let mut identity_before=Vec::new();if renumber{for id in &ids{identity_before.push(case.app.collection("private_peers").find_one(doc!{"_id":format!("{owner}:{id}")}).projection(identity_projection.clone()).await?.context("fixture identity missing")?);}}
        let rules_before=if renumber{case.app.collection("access_rulebooks").find_one(doc!{"user_id":owner}).await?}else{None};
        let order:Vec<usize>=if gated{vec![2,1,0]}else if paired{vec![1,0]}else{vec![1,2,0]};
        for i in order {
            let name = format!("{network}-node-{i}");

            let profile = json!({"server":base,"workspace":owner.to_hex(),"peer_id":format!("{owner}:{}",ids[i]),"token":token,"allow_insecure_http_for_tests":true}).to_string();
            let ip = format!("198.18.10.{}", i + 2);
            let mount = format!("type=bind,src={binary},dst=/worker,readonly");
            let runtime_mount=format!("type=bind,src={runtime_root},dst=/fixture-runtime,readonly");
            let entrypoint=format!("/fixture-runtime/{runtime_loader}");
            let env_profile = format!("PORTHUB_TEST_PROFILE={profile}");
            let env_role = format!("PORTHUB_TEST_ROLE={}", if renumber{if i==0{"renumber-consumer"}else{"renumber-provider"}}else if gated{if i==0{"relay-origin-consumer"}else if i==1{"relay-origin-provider"}else{"relay-origin-bootstrap"}}else if paired{if i==0{"private-consumer"}else{"private-provider"}}else if i==0{"consumer"}else{"exit"});
            let env_gate=format!("PORTHUB_TEST_PROVIDER_GATE={}",if gated&&i==1{"1"}else{"0"});
            let env_bootstrap_source=format!("PORTHUB_TEST_RELAY_BOOTSTRAP_SOURCE=10.234.240.{}",i+10);
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
                "--env", "PORTHUB_TEST_OWNED_NETNS=1", "--env", &env_profile, "--env", &env_public, "--env", &env_role, "--env", &env_target, "--env", &env_control, "--env", env_peer_target, "--env", &env_nonce, "--env", &env_gate, "--env", &env_bootstrap_source,
                "--mount", &mount, "--mount", &runtime_mount, "--entrypoint", &entrypoint, &image, "--library-path", "/fixture-runtime", "/worker", "--ignored", "--exact", "isolated_exit_worker", "--nocapture"])).await?;
            containers.push(name.clone());
            if i > 0 && !paired { docker(args(&["network", "connect", "--ip", &format!("203.0.113.{}",i+1), &external, &name])).await?; }
            docker(args(&["start", &name])).await?;
        }
        let consumer = containers.last().unwrap();
        if gated {
            let provider=containers.get(1).context("owned provider absent")?;
            async fn wait_phase_for(name:&str,phase:&str,budget:Duration)->Result<String> {
                tokio::time::timeout(budget,async{loop{let logs=docker(args(&["logs",name])).await?;if logs.contains(phase){return Ok::<_,anyhow::Error>(logs);}tokio::time::sleep(Duration::from_millis(25)).await;}}).await.with_context(||format!("owned relay handshake phase timeout: {phase}"))?
            }
            async fn wait_phase(name:&str,phase:&str)->Result<String>{wait_phase_for(name,phase,Duration::from_secs(8)).await}
            let bootstrap_deadline=tokio::time::Instant::now()+Duration::from_secs(20);
            for endpoint in [provider,consumer]{wait_phase_for(endpoint,"native_relay_origin negotiated=true",bootstrap_deadline.saturating_duration_since(tokio::time::Instant::now())).await?;}
            docker(args(&["exec",consumer,"sh","-c","test ! -e /state/release-send && touch /state/release-send"])).await?;
            println!("fault_injected_relay phase=both_real_relay_connections_established");
            wait_phase(provider,"phase=retained_before_pair").await?;
            println!("fault_injected_relay phase=first_payload_retained_before_pair");
            docker(args(&["exec",provider,"sh","-c","test ! -e /state/release-pair && touch /state/release-pair"])).await?;
            let logs=wait_phase(provider,"phase=retained_wait_native").await?;
            let waiting=logs.lines().find(|line|line.contains("phase=retained_wait_native")).context("native wait observation missing")?;
            let generation=waiting.split_whitespace().find_map(|part|part.strip_prefix("generation=")).context("bound native generation missing")?.parse::<u64>()?;
            ensure!(generation>0,"retained payload bound empty native plan");
            wait_phase(provider,&format!("phase=native_apply_acked generation={generation} count=1")).await?;
            println!("fault_injected_relay phase=payload_retained_with_real_kernel_ack_and_native_veto");
            docker(args(&["exec",provider,"sh","-c","test ! -e /state/release-native && touch /state/release-native"])).await?;
        }
        let status = tokio::time::timeout(Duration::from_secs(180), docker(args(&["wait", consumer]))).await.context("exit consumer timed out")??;
        let logs = docker(args(&["logs", consumer])).await?;
        println!("{logs}");
        ensure!(status == "0", "exit consumer failed with status {status}");
        if gated {
            ensure!(udp_received.load(std::sync::atomic::Ordering::SeqCst)==1,"first owned UDP was retried or duplicated");
            let provider=containers.get(1).context("owned provider missing")?;let logs=docker(args(&["logs",provider])).await?;
            ensure!(logs.contains("native_relay_origin negotiated=true")&&logs.contains("native_relay_origin decoded_records=")&&logs.contains("phase=pending_native_write_complete"),"actual negotiated relay/pending native delivery witness missing");
            println!("{logs}");println!("fault_injected_relay payload=true negotiated_origin=true single_udp=true native_write_after_ack=true");
        }

        if renumber {
            ensure!(logs.contains("native_auto_renumber new_ip_payload=true old_source_no_escape=true foreign_route_preserved=true"),"native renumber consumer witness missing");
            for (id,before) in ids.iter().zip(&identity_before){ensure!(case.app.collection("private_peers").find_one(doc!{"_id":format!("{owner}:{id}")}).projection(identity_projection.clone()).await?.as_ref()==Some(before),"renumber changed enrollment identity/credentials");}
            ensure!(case.app.collection("access_rulebooks").find_one(doc!{"user_id":owner}).await?==rules_before,"renumber changed rules");
            let prefs=case.app.collection("private_networks").find_one(doc!{"_id":owner.to_hex()}).await?.context("renumber preferences missing")?;
            ensure!(prefs.get_str("dns_suffix")?=="phub"&&prefs.get_str("native_fixture_preference")?=="preserved","renumber changed DNS/preference identity");
            println!("actual_gateway_worker_renumber identity_credentials_rules_dns_preserved=true os_dns_combined=false");
        }
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
    if let Some(mut recovery)=recovery{
        let _=recovery_stop.send(true);
        if !matches!(tokio::time::timeout(Duration::from_secs(5),&mut recovery).await,Ok(Ok(()))){
            recovery.abort();let _=recovery.await;cleanup_errors.push("renumber-worker-reap");
        }
    }
    if case.db.drop().await.is_err(){cleanup_errors.push("case-db-drop");}
    println!("owned_native_fixture_cleanup={} scenario={}",cleanup_errors.is_empty(),if renumber{"renumber"}else if paired{"peers"}else{"exits"});
    if !cleanup_errors.is_empty(){return Err(result.err().unwrap_or_else(||anyhow::anyhow!("native fixture cleanup failed")).context(format!("fixture cleanup categories: {cleanup_errors:?}")));}
    result
}
use std::future::IntoFuture;
