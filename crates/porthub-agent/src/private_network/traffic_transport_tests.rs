//! Retained local carrier proof: real RTC/gateway TX and controller uploads.
//! No TUN, routes, host service or real enrollment is created. RX events are
//! verified, but this fixture does not execute the runtime's TUN/RX owner loop.
use super::*;
use anyhow::{ensure, Context};
use serde::Deserialize;
use sha2::Digest;
use std::{net::Ipv4Addr, path::PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    nonce: String,
    base: String,
    workspace: String,
    peers: [String; 2],
    token: String,
    complete: PathBuf,
    fixture_sha256: String,
    runtime_sha256: String,
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", sha2::Sha256::digest(bytes))
}

#[tokio::test]
#[ignore = "owned actual-App parent private_traffic_carriers supplies loopback API and private input"]
async fn actual_direct_and_gateway_carriers_upload_observed_tx() -> Result<()> {
    let input_path = PathBuf::from(std::env::var("PORTHUB_PRIVATE_TRAFFIC_CARRIER_INPUT")?);
    let bytes = crate::profile::read_private(&input_path)?;
    ensure!(bytes.len() <= 16_384, "carrier fixture input limit");
    let input: Input = serde_json::from_slice(&bytes)?;
    ensure!(
        input.nonce.len() == 32 && input.nonce.bytes().all(|b| b.is_ascii_hexdigit()),
        "carrier nonce guard"
    );
    ensure!(
        input.fixture_sha256 == digest(include_bytes!("traffic_transport_tests.rs"))
            && input.runtime_sha256 == digest(include_bytes!("runtime.rs")),
        "carrier compiled source guard"
    );
    let base = url::Url::parse(&input.base)?;
    ensure!(
        base.scheme() == "http"
            && base.host_str() == Some("127.0.0.1")
            && base.port().is_some()
            && base.username().is_empty()
            && base.password().is_none()
            && base.query().is_none()
            && base.fragment().is_none()
            && base.path() == "/",
        "carrier loopback API guard"
    );
    ensure!(
        input.complete.parent() == input_path.parent() && !input.complete.exists(),
        "carrier owned completion guard"
    );
    ensure!(
        input.peers[0] != input.peers[1]
            && input
                .peers
                .iter()
                .all(|id| porthub_mesh::traffic_report::peer_id(id)
                    && id.starts_with(&format!("{}:", input.workspace))),
        "carrier peer binding"
    );
    let mut builder = tempfile::Builder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700))
    };
    let own = builder.tempdir()?;
    let cancel = CancellationToken::new();
    let mut tasks = JoinSet::new();
    let mut sessions: Vec<Sessions> = Vec::new();
    let result = async {
        let mut trackers = Vec::new();
        let mut inputs = Vec::new();
        let mut relay_senders = Vec::new();
        let mut interface_guards = Vec::new();
        for index in 0..2 {
            let profile = Profile { server: input.base.clone(), peer_id: input.peers[index].clone(), workspace: input.workspace.clone(), token: input.token.clone(), account_email: None, fallback_servers: Vec::new(), allow_insecure_http_for_tests: true };
            let profile_path = own.path().join(format!("node{index}.json"));
            crate::profile::write_private(&profile_path, &serde_json::to_vec(&profile)?, false)?;
            let tracker = super::super::traffic::Tracker::new(&profile_path);
            let live: Sessions = Default::default();
            let (events, receiver) = mpsc::channel(4096);
            let (interfaces, interface_rx) = watch::channel(vec!["127.0.0.1:0".parse()?]);
            interface_guards.push(interfaces);
            let (relay_config, relay_rx) = watch::channel(None);
            let (relay, relay_input) = super::super::relay::channel();
            let instance = controller::nonce()?;
            tasks.spawn(super::super::relay::run(profile.clone(), instance.clone(), relay.clone(), relay_input, relay_rx, events.clone(), cancel.child_token()));
            tasks.spawn(controller::run_watched_identity(profile, interface_rx, live.clone(), events, relay_config, controller::LocalIdentity { traffic: Some(tracker.clone()), instance, certificate: porthub_mesh::Identity::new()? }, cancel.child_token()));
            trackers.push(tracker); sessions.push(live); inputs.push(receiver); relay_senders.push(relay);
        }
        let mut counters = Vec::new();
        for (index, receiver) in inputs.iter_mut().enumerate() {
            let snapshot = tokio::time::timeout(Duration::from_secs(15), async {
                loop { match receiver.recv().await { Some(Event::Snapshot(value)) => break Ok::<_,anyhow::Error>(value), Some(_) => {}, None => anyhow::bail!("carrier snapshot owner closed") } }
            }).await??;
            ensure!(snapshot.peers.iter().any(|p| p.id == input.peers[1-index]), "carrier actual snapshot missing peer");
            counters.push(trackers[index].reconcile(snapshot.peers.into_iter().filter(|p|p.id != input.peers[index]).map(|p|p.id)));
        }
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if sessions[0].read().await.get(&input.peers[1]).is_some_and(|s|s.state()==porthub_mesh::State::Ready)
                    && sessions[1].read().await.get(&input.peers[0]).is_some_and(|s|s.state()==porthub_mesh::State::Ready)
                    && relay_senders.iter().all(|r|r.is_ready()) { break Ok::<_,anyhow::Error>(()); }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.context("carrier actual transports ready deadline")??;
        for index in 0..2 { ensure!(!sessions[index].read().await[&input.peers[1-index]].is_relay(), "carrier direct RTC did not win"); }
        let ips: [Ipv4Addr;2] = ["10.203.0.10".parse()?, "10.203.0.11".parse()?];
        let mut plans = Vec::new(); let mut outputs = Vec::new();
        for index in 0..2 {
            let (sender, packets) = mpsc::channel(16);
            let plan = StreamCarrierPlan { source: Some(ips[index]), valid_until: Some(Instant::now()+Duration::from_secs(60)), routes: HashMap::from([(ips[1-index], (input.peers[1-index].clone(),true,counters[index].get(&input.peers[1-index]).cloned()))]) };
            let (updates, plan_rx) = watch::channel(plan);
            tasks.spawn(stream_carrier(packets, plan_rx, sessions[index].clone(), relay_senders[index].clone(), cancel.child_token()));
            plans.push(updates); outputs.push(sender);
        }
        let mut observed = [[0u64;2];2];
        for direct in [true,false] {
            for index in 0..2 {
                plans[index].send_modify(|plan|plan.routes.get_mut(&ips[1-index]).unwrap().1=direct);
                let payload = bytes::Bytes::from(vec![if direct {17} else {29};64]);
                outputs[index].send(porthub_mesh::streams::Datagram { address: ips[1-index], payload: payload.clone() }).await?;
                let received = tokio::time::timeout(Duration::from_secs(3), async {
                    loop { match inputs[1-index].recv().await {
                        Some(Event::Packet{peer,bytes,carrier_direct,..}) => break Ok::<_,anyhow::Error>((peer,bytes,carrier_direct)),
                        Some(_) => {}, None => anyhow::bail!("carrier receive owner closed")
                    }}
                }).await.context("carrier receive deadline")??;
                ensure!(received.0==input.peers[index] && received.2==direct, "carrier path/peer mismatch");
                let decoded = porthub_mesh::control_packet::decode(porthub_mesh::control_packet::STREAM,received.1.clone()).context("carrier envelope rejected")?;
                ensure!(decoded.source==ips[index] && decoded.destination==ips[1-index] && decoded.payload==payload, "carrier byte identity mismatch");
                observed[index][usize::from(!direct)] += received.1.len() as u64;
            }
        }
        ensure!(observed==[[84,84],[84,84]], "carrier expected observed byte counts");
        // Public production sampler path, not Counter::add or fabricated Rows.
        for tracker in &trackers { let sample=CancellationToken::new();sample.cancel();tracker.clone().run(sample).await; }
        tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                match crate::profile::read_private(&input.complete) {
                    Ok(bytes) => {let value:serde_json::Value=serde_json::from_slice(&bytes)?;ensure!(value["nonce"]==input.nonce && value["uploaded"]==true,"carrier completion binding");break Ok::<_,anyhow::Error>(());},
                    Err(_) if !input.complete.exists()=>{}, Err(e)=>return Err(e)
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }).await.context("carrier automatic controller upload deadline")??;
        println!("PRIVATE_TRAFFIC_CARRIER_PROOF direct_tx_bytes=168 relay_tx_bytes=168 actual_rx_bytes=336 controller_upload=true runtime_rx_owner_exercised=false");
        Ok::<_,anyhow::Error>(())
    }.await;
    cancel.cancel();
    let joined = tokio::time::timeout(Duration::from_secs(5), async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    if joined.is_err() {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    for live in &sessions {
        for session in live.write().await.drain().map(|(_, s)| s) {
            tokio::time::timeout(Duration::from_secs(3), session.close()).await?;
        }
    }
    result
}
