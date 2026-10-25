//! Real native API+Mongo signaling followed by real native UDP packet transport.
//! No privileged host networking or deployed agent is modified.
use anyhow::{ensure, Result};
use mongodb::bson::{doc, oid::ObjectId};
use porthub_agent::{
    private_network::controller::{self, Event, Sessions},
    private_profile::Profile,
};
use porthub_api::{config::Config, domain::workspaces::token_digest};
use std::time::Duration;
use tokio::{sync::mpsc, task::JoinSet};
use tokio_util::sync::CancellationToken;
#[allow(dead_code)]
mod support;
use support::Case;
#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn enrolled_native_agents_discover_each_other_and_transfer_without_gateway_payload(
) -> Result<()> {
    exercise_discovery(false).await
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn changed_underlay_is_used_after_failure_without_replacing_a_healthy_peer() -> Result<()> {
    exercise_discovery(true).await
}

async fn exercise_discovery(network_change: bool) -> Result<()> {
    let case = Case::new(Config {
        private_transport: porthub_api::private_transport::Settings::parse(
            "[]",
            "",
            "native-controller-relay-secret-0123456789abcdef",
        ),
        ..Default::default()
    })
    .await?;
    let cancel = CancellationToken::new();
    let mut tasks = JoinSet::new();
    let gateway_cancel = CancellationToken::new();
    let mut gateway = None;
    let result=async {
        let (owner,_)=case.user("native-packet-owner@test.invalid","user").await?;
        let ids=[ObjectId::new(),ObjectId::new()];let peers:Vec<_>=ids.iter().map(|mid|format!("{owner}:{mid}")).collect();
        let token="native-packet-fixture-token-0123456789abcdef";
        for (i,mid) in ids.iter().enumerate() {
            case.app.collection("machines").insert_one(doc!{"_id":mid,"user_id":owner,"name":format!("Node{i}"),"token":"unused-public-token"}).await?;
            case.app.collection("private_peers").insert_one(doc!{"_id":&peers[i],"workspace_id":owner,"machine_id":mid,"owner_id":owner,"ip":format!("10.203.0.{}",i+10),"enabled":true,"credential_hash":token_digest(token)}).await?;
        }
        let group=ObjectId::new();case.app.collection("machine_groups").insert_one(doc!{"_id":group,"user_id":owner}).await?;
        case.app.collection("access_rulebooks").insert_one(doc!{"_id":ObjectId::new(),"user_id":owner,"group_id":group.to_hex(),"rules":[{"id":"http","name":"HTTP","sources":[{"kind":"machine","id":ids[0].to_hex()}],"destinations":[{"kind":"machine","id":ids[1].to_hex()}],"ports":"8000"}]}).await?;
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let base=format!("http://{}",listener.local_addr()?);
        let app=case.router.clone();let stop=gateway_cancel.clone();gateway=Some(tokio::spawn(async move {axum::serve(listener,app).with_graceful_shutdown(stop.cancelled_owned()).await.map_err(anyhow::Error::from)}));
        let mut sessions:Vec<Sessions>=Vec::new();let mut receivers=Vec::new();let mut interface_updates=Vec::new();
        for id in &peers {
            let profile=Profile{server:base.clone(),peer_id:id.clone(),workspace:owner.to_hex(),token:token.into(),account_email:None,fallback_servers:vec![],allow_insecure_http_for_tests:true};
            let live:Sessions=Default::default();let (output,input)=mpsc::channel(4096);
            if network_change {
                let initial=if interface_updates.is_empty() {Vec::new()} else {vec!["127.0.0.1:0".parse()?]};
                let (updates,interfaces)=tokio::sync::watch::channel(initial);
                tasks.spawn(controller::run_watched_instance(profile,interfaces,live.clone(),output,controller::nonce()?,cancel.child_token()));
                interface_updates.push(updates);
            } else {
                tasks.spawn(controller::run(profile,vec!["127.0.0.1:0".parse()?],live.clone(),output,cancel.child_token()));
            }
            sessions.push(live);receivers.push(input);
        }
        if network_change {
            // The agent still registers and accepts policy while no underlay
            // address exists. Coming online wakes discovery without a restart.
            next_snapshot(&mut receivers[0]).await?;
            ensure!(sessions[0].read().await.is_empty());
            interface_updates[0].send(vec!["127.0.0.1:0".parse()?])?;
        }
        tokio::time::timeout(Duration::from_secs(15),async {
            loop {
                let ready0=sessions[0].read().await.get(&peers[1]).is_some_and(|peer|peer.state()==porthub_mesh::State::Ready);
                let ready1=sessions[1].read().await.get(&peers[0]).is_some_and(|peer|peer.state()==porthub_mesh::State::Ready);
                if ready0 && ready1 {break Ok::<_,anyhow::Error>(());}
                tokio::select! {
                    finished=tasks.join_next()=>{anyhow::bail!("private controller stopped: {finished:?}")},
                    _=tokio::time::sleep(Duration::from_millis(20))=>{}
                }
            }
        }).await??;
        let mut a=sessions[0].read().await[&peers[1]].clone();let mut b=sessions[1].read().await[&peers[0]].clone();
        if network_change {
            let previous=a.description().sdp;
            while receivers[0].try_recv().is_ok() {}
            interface_updates[0].send(vec!["127.0.0.2:0".parse()?])?;
            next_snapshot(&mut receivers[0]).await?;
            let same=sessions[0].read().await[&peers[1]].clone();
            ensure!(same.description().sdp==previous && same.state()==porthub_mesh::State::Ready,
                "background interface refresh replaced a healthy peer");
            a.send(vec![0x45;1380].into())?;
            next_packet(&mut receivers[1]).await?;
            // Simulate loss of both old bound sockets. The replacement must
            // use the updated address and retain the enrolled peer identity.
            a.close().await;b.close().await;
            tokio::time::timeout(Duration::from_secs(35),async {
                loop {
                    let left=sessions[0].read().await.get(&peers[1]).cloned();
                    let right=sessions[1].read().await.get(&peers[0]).cloned();
                    if let (Some(left),Some(right))=(left,right) {
                        if left.state()==porthub_mesh::State::Ready && right.state()==porthub_mesh::State::Ready {
                            ensure!(left.description().sdp.contains("127.0.0.2"),"replacement reused a stale local address");
                            ensure!(left.description().sdp!=previous,"replacement reused old ICE credentials");
                            a=left;b=right;
                            break anyhow::Ok(());
                        }
                    }
                    tokio::select! {
                        finished=tasks.join_next()=>anyhow::bail!("private controller stopped: {finished:?}"),
                        _=tokio::time::sleep(Duration::from_millis(20))=>{}
                    }
                }
            }).await??;
        }
        ensure!(a.description().sdp.contains(" typ relay") && b.description().sdp.contains(" typ relay"),"background discovery did not prepare TURN candidates");
        ensure!(!a.is_relay() && !b.is_relay(), "LAN candidates did not win over the prepared relay");
        // Stop the entire gateway before transferring: only the pre-discovered
        // direct peer sockets can deliver this payload.
        gateway_cancel.cancel(); gateway.take().unwrap().await??;
        let (mut left,mut right)=(receivers.remove(0),receivers.remove(0));
        while left.try_recv().is_ok() {} while right.try_recv().is_ok() {}
        for i in 0..1024u32 {
            let mut bytes=vec![(i%251)as u8;1380];bytes[0]=0x45;bytes[4..8].copy_from_slice(&i.to_be_bytes());
            a.send(bytes.clone().into())?;
            let received=tokio::time::timeout(Duration::from_secs(2),async {loop {match right.recv().await {Some(Event::Packet{peer,bytes,..})=>break Ok::<_,anyhow::Error>((peer,bytes)),Some(_)=>{},None=>anyhow::bail!("right packet owner closed")}}}).await??;
            ensure!(received.0==peers[0] && received.1.as_ref()==bytes);
            b.send(received.1)?;
            let received=tokio::time::timeout(Duration::from_secs(2),async {loop {match left.recv().await {Some(Event::Packet{peer,bytes,..})=>break Ok::<_,anyhow::Error>((peer,bytes)),Some(_)=>{},None=>anyhow::bail!("left packet owner closed")}}}).await??;
            ensure!(received.0==peers[1] && received.1.as_ref()==bytes);
        }
        ensure!(a.statistics().await?.sent_bytes==1024*1380);
        Ok(())
    }.await;
    gateway_cancel.cancel();
    if let Some(gateway) = gateway {
        gateway.abort();
    }
    cancel.cancel();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn native_gateway_fallback_authenticates_leases_and_blocks_spoofed_packet_sources(
) -> Result<()> {
    use axum::http::StatusCode;
    use porthub_agent::private_network::relay;
    use serde_json::json;
    let case = Case::new(Config::default()).await?;
    let cancel = CancellationToken::new();
    let mut tasks = JoinSet::new();
    let result=async {
        let (owner,cookie)=case.user("native-relay-owner@test.invalid","user").await?;
        let ids=[ObjectId::new(),ObjectId::new()];let peers:Vec<_>=ids.iter().map(|mid|format!("{owner}:{mid}")).collect();
        let token="native-relay-fixture-token-0123456789abcdef";
        for (i,mid) in ids.iter().enumerate() {
            case.app.collection("machines").insert_one(doc!{"_id":mid,"user_id":owner,"name":format!("Node{i}"),"token":"unused-public-token"}).await?;
            case.app.collection("private_peers").insert_one(doc!{"_id":&peers[i],"workspace_id":owner,"machine_id":mid,"owner_id":owner,"ip":format!("10.203.0.{}",i+10),"enabled":true,"credential_hash":token_digest(token)}).await?;
        }
        let group=ObjectId::new();case.app.collection("machine_groups").insert_one(doc!{"_id":group,"user_id":owner}).await?;
        let book=ObjectId::new();case.app.collection("access_rulebooks").insert_one(doc!{"_id":book,"user_id":owner,"group_id":group.to_hex(),"rules":[{"id":"http","name":"HTTP","sources":[{"kind":"machine","id":ids[0].to_hex()}],"destinations":[{"kind":"machine","id":ids[1].to_hex()}],"ports":"8000"}]}).await?;
        for peer in &peers {
            case.status("POST","/api/access/private/sync","",json!({"peer_id":peer,"token":token,"fingerprint":vec!["AB";32].join(":"),"instance":"relay-instance-0123456789"}),StatusCode::OK).await?;
        }
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let base=format!("http://{}",listener.local_addr()?);
        let app=case.router.clone();let stop=cancel.clone();tasks.spawn(async move {axum::serve(listener,app).with_graceful_shutdown(stop.cancelled_owned()).await.map_err(anyhow::Error::from)});
        // The browser/public token and stale process identities cannot upgrade.
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        for (credential,instance) in [("unused-public-token","relay-instance-0123456789"),(token,"stale-instance-0123456789")] {
            let request=base.replacen("http:","ws:",1).to_owned()+"/api/access/private/relay";
            let mut request=request.into_client_request()?;
            request.headers_mut().insert("x-porthub-peer",peers[0].parse()?);
            request.headers_mut().insert("x-porthub-instance",instance.parse()?);
            request.headers_mut().insert("authorization",format!("Bearer {credential}").parse()?);
            ensure!(tokio_tungstenite::connect_async(request).await.is_err());
        }
        let mut senders=Vec::new();let mut receivers=Vec::new();
        for peer in &peers {
            let profile=Profile{server:base.clone(),peer_id:peer.clone(),workspace:owner.to_hex(),token:token.into(),account_email:None,fallback_servers:vec![],allow_insecure_http_for_tests:true};
            let (sender,input)=relay::channel();let (output,events)=mpsc::channel(16);
            tasks.spawn(relay::run(profile,"relay-instance-0123456789".into(),sender.clone(),input,output,cancel.child_token()));
            senders.push(sender);receivers.push(events);
        }
        tokio::time::timeout(Duration::from_secs(3),async {while !senders.iter().all(|sender|sender.is_ready()) {tokio::time::sleep(Duration::from_millis(10)).await;}}).await?;
        let mut packet=vec![0u8;40];packet[0]=0x45;packet[2..4].copy_from_slice(&40u16.to_be_bytes());packet[9]=6;
        packet[12..16].copy_from_slice(&[10,203,0,10]);packet[16..20].copy_from_slice(&[10,203,0,11]);
        // Establish the outbound relay in the background before any data frame.
        tokio::time::timeout(Duration::from_secs(3),async {
            loop {if senders[0].send(&peers[1],&packet).is_ok() {break;}tokio::time::sleep(Duration::from_millis(10)).await;}
        }).await?;
        let right=&mut receivers[1];
        let received=tokio::time::timeout(Duration::from_secs(3),right.recv()).await?.ok_or_else(||anyhow::anyhow!("relay stopped"))?;
        let Event::Packet{peer,bytes,..}=received else {anyhow::bail!("unexpected relay event");};ensure!(peer==peers[0] && bytes.as_ref()==packet);
        let mut forged=packet.clone();forged[12]=192;senders[0].send(&peers[1],&forged)?;
        ensure!(tokio::time::timeout(Duration::from_millis(150),right.recv()).await.is_err());
        // Publish an updated, empty policy lease through authenticated sync.
        case.app.collection("access_rulebooks").delete_one(doc!{"_id":book}).await?;
        case.status("POST","/api/access/private/sync","",json!({"peer_id":peers[0],"token":token,"fingerprint":vec!["AB";32].join(":"),"instance":"relay-instance-0123456789"}),StatusCode::OK).await?;
        senders[0].send(&peers[1],&packet)?;
        ensure!(tokio::time::timeout(Duration::from_millis(150),right.recv()).await.is_err());
        let _=cookie;Ok(())
    }.await;
    cancel.cancel();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    case.db.drop().await?;
    result
}

async fn next_snapshot(input: &mut mpsc::Receiver<Event>) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match input.recv().await {
                Some(Event::Snapshot(_)) => return anyhow::Ok(()),
                Some(_) => {}
                None => anyhow::bail!("private packet owner closed"),
            }
        }
    })
    .await?
}
async fn next_packet(input: &mut mpsc::Receiver<Event>) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match input.recv().await {
                Some(Event::Packet { .. }) => return anyhow::Ok(()),
                Some(_) => {}
                None => anyhow::bail!("private packet owner closed"),
            }
        }
    })
    .await?
}
