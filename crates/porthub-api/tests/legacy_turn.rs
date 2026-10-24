use anyhow::{ensure, Context, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId};
use porthub_api::{config::Config, domain::workspaces::token_digest, private_transport::Settings};
use serde_json::{json, Value};
use std::{process::Stdio, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
mod support;
use support::Case;
#[test]
fn turn_tcp_framing_preserves_split_coalesced_and_padded_messages() {
    use porthub_api::legacy_turn::Framing;
    let mut frame = Framing::default();
    let mut stun = vec![0u8; 24];
    stun[1] = 1;
    stun[3] = 4;
    let channel = vec![0x40, 1, 0, 3, 1, 2, 3, 0];
    frame.push(&stun[..3]).unwrap();
    assert!(frame.packet().unwrap().is_none());
    frame.push(&[&stun[3..], &channel].concat()).unwrap();
    assert_eq!(frame.packet().unwrap(), Some(stun));
    assert_eq!(frame.packet().unwrap(), Some(channel));
    assert!(frame.packet().unwrap().is_none());
    frame.push(&[0x80, 0, 0, 0]).unwrap();
    assert!(frame.packet().is_err());
}
#[tokio::test]
#[ignore = "requires isolated MongoDB and PORTHUB_TEST_GO_TURN_BINARY"]
async fn existing_pion_peers_exchange_pinned_dtls_packets_through_native_turn_websockets(
) -> Result<()> {
    let executable = std::env::var_os("PORTHUB_TEST_GO_TURN_BINARY")
        .context("build the development-only TURN reference fixture")?;
    let secret = "native-turn-reference-secret-0123456789abcdef";
    let case = Case::new(Config {
        private_transport: Settings::parse("[]", "", secret),
        ..Default::default()
    })
    .await?;
    let mut child = tokio::process::Command::new(executable)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .env("PORTHUB_COMPAT_TRACE", "1")
        .kill_on_drop(true)
        .spawn()?;
    let mut output = BufReader::new(child.stdout.take().unwrap()).lines();
    let cancel = tokio_util::sync::CancellationToken::new();
    let mut server = None;
    let result=async {
        let first=tokio::time::timeout(Duration::from_secs(5),output.next_line()).await??.context("TURN reference did not publish certificate fingerprints")?;
        let fingerprints:Value=serde_json::from_str(&first)?;
        let (owner,_)=case.user("legacy-turn-owner@test.invalid","user").await?;
        let ids=[ObjectId::new(),ObjectId::new()];let peers:Vec<_>=ids.iter().map(|id|format!("{owner}:{id}")).collect();let token="legacy-turn-private-token-0123456789abcdef";
        for (i,id) in ids.iter().enumerate() {
            case.app.collection("machines").insert_one(doc!{"_id":id,"user_id":owner,"name":format!("Legacy{i}"),"token":"public-token-unused"}).await?;
            case.app.collection("private_peers").insert_one(doc!{"_id":&peers[i],"workspace_id":owner,"machine_id":id,"owner_id":owner,"ip":format!("10.203.0.{}",i+10),"enabled":true,"credential_hash":token_digest(token)}).await?;
        }
        let group=ObjectId::new();case.app.collection("machine_groups").insert_one(doc!{"_id":group,"user_id":owner}).await?;
        case.app.collection("access_rulebooks").insert_one(doc!{"_id":ObjectId::new(),"user_id":owner,"group_id":group.to_hex(),"rules":[{"id":"test","name":"Test","sources":[{"kind":"machine","id":ids[0].to_hex()}],"destinations":[{"kind":"machine","id":ids[1].to_hex()}],"ports":"8000"}]}).await?;
        let mut contexts=Vec::new();
        for (i,peer) in peers.iter().enumerate() {
            let response=case.status("POST","/api/access/private/sync","",json!({"peer_id":peer,"token":token,"fingerprint":fingerprints["fingerprints"][i],"instance":format!("legacy-turn-instance-000{i}")}),StatusCode::OK).await?;
            contexts.push(response["ice_servers"].clone());
        }
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;
        let router=case.router.clone();let stop=cancel.clone();server=Some(tokio::spawn(async move {axum::serve(listener,router).with_graceful_shutdown(stop.cancelled_owned()).await}));
        let request=json!({"relay_url":format!("ws://{address}/api/access/private/relay"),"ice_servers":contexts});
        let mut input=child.stdin.take().unwrap();input.write_all(format!("{request}\n").as_bytes()).await?;drop(input);
        let report=tokio::time::timeout(Duration::from_secs(20),output.next_line()).await??.context("legacy TURN/DTLS packet exchange failed")?;
        let report:Value=serde_json::from_str(&report)?;
        ensure!(report["packets"]==256 && report["bytes"]==256*1380 && report["both_relay"]==true);
        ensure!(tokio::time::timeout(Duration::from_secs(3),child.wait()).await??.success());
        // Replace both enrolled identities with native peers, then force the
        // same gateway-only path. Neither peer binds a local UDP socket.
        let identities=[porthub_mesh::Identity::new()?,porthub_mesh::Identity::new()?];
        for (i,peer) in peers.iter().enumerate() {
            case.status("POST","/api/access/private/sync","",json!({"peer_id":peer,"token":token,"fingerprint":identities[i].fingerprint(),"instance":format!("native-turn-instance-000{i}")}),StatusCode::OK).await?;
        }
        let mut allocations=Vec::new();
        for context in &contexts {
            let credential=context.as_array().context("missing ICE context")?.last().context("missing TURN credential")?;
            allocations.push(porthub_mesh::relay::Allocation::connect(&format!("ws://{address}/api/access/private/relay"),credential["username"].as_str().unwrap(),credential["credential"].as_str().unwrap(),true).await?);
        }
        let (a,mut a_rx)=porthub_mesh::udp::Session::bind_relay(allocations[0].clone(),&peers[0],&peers[1],identities[0].clone(),identities[1].fingerprint())?;
        let (b,mut b_rx)=porthub_mesh::udp::Session::bind_relay(allocations[1].clone(),&peers[1],&peers[0],identities[1].clone(),identities[0].fingerprint())?;
        ensure!(a.description().sdp.contains(" typ relay"));
        ensure!(b.description().sdp.contains(" typ relay"));
        a.remote(&peers[1],b.description()).await?;
        b.remote(&peers[0],a.description()).await?;
        tokio::time::timeout(Duration::from_secs(8),async { a.ready().await?;b.ready().await?;anyhow::Ok(()) }).await??;
        ensure!(a.is_relay() && b.is_relay());
        for index in 0..256 {
            let packet=axum::body::Bytes::from(vec![(index%251) as u8;1380]);
            a.send(packet.clone())?;
            ensure!(tokio::time::timeout(Duration::from_secs(2),b_rx.recv()).await?==Some(packet.clone()));
            b.send(packet.clone())?;
            ensure!(tokio::time::timeout(Duration::from_secs(2),a_rx.recv()).await?==Some(packet));
        }
        a.close().await;b.close().await;
        for allocation in allocations { allocation.close().await; }
        let go=std::env::var_os("PORTHUB_TEST_GO_MESH_BINARY").context("build Go peer reference fixture")?;
        let mut go=tokio::process::Command::new(go).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).kill_on_drop(true).spawn()?;
        let mut lines=BufReader::new(go.stdout.take().unwrap()).lines();
        let fingerprint:Value=serde_json::from_str(&tokio::time::timeout(Duration::from_secs(3),lines.next_line()).await??.context("Go reference fingerprint missing")?)?;
        case.status("POST","/api/access/private/sync","",json!({"peer_id":peers[0],"token":token,"fingerprint":fingerprint["fingerprint"],"instance":"mixed-turn-go-instance-0000"}),StatusCode::OK).await?;
        let credential=contexts[1].as_array().unwrap().last().unwrap();
        let allocation=porthub_mesh::relay::Allocation::connect(&format!("ws://{address}/api/access/private/relay"),credential["username"].as_str().unwrap(),credential["credential"].as_str().unwrap(),true).await?;
        let (native,mut packets)=porthub_mesh::udp::Session::bind_relay(allocation.clone(),&peers[1],&peers[0],identities[1].clone(),fingerprint["fingerprint"].as_str().unwrap())?;
        let mut input=go.stdin.take().unwrap();
        input.write_all(format!("{}\n",json!({"role":"offer","fingerprint":identities[1].fingerprint(),"relay_url":format!("ws://{address}/api/access/private/relay"),"ice_servers":contexts[0]})).as_bytes()).await?;
        let offer=serde_json::from_str(&tokio::time::timeout(Duration::from_secs(5),lines.next_line()).await??.context("Go TURN offer missing")?)?;
        native.remote(&peers[0],offer).await?;
        input.write_all(format!("{}\n",serde_json::to_string(&native.description())?).as_bytes()).await?;
        tokio::time::timeout(Duration::from_secs(8),native.ready()).await??;
        ensure!(tokio::time::timeout(Duration::from_secs(3),lines.next_line()).await??.is_some());
        ensure!(native.is_relay());
        for index in 0..256 {
            let packet=axum::body::Bytes::from(vec![(index%251) as u8;1380]);native.send(packet.clone())?;
            ensure!(tokio::time::timeout(Duration::from_secs(2),packets.recv()).await?==Some(packet));
        }
        input.write_all(b"{}\n").await?;drop(input);
        ensure!(tokio::time::timeout(Duration::from_secs(3),go.wait()).await??.success());
        native.close().await;allocation.close().await;
        Ok(())
    }.await;
    cancel.cancel();
    if let Some(server) = server {
        server.abort();
    }
    let _ = child.kill().await;
    let _ = child.wait().await;
    case.db.drop().await?;
    result
}
