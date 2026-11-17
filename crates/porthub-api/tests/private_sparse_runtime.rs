//! Real isolated-Mongo API + HTTP controller + portable native TCP + pinned
//! carrier/application integration. No host TUN/routes/resolver/service changes.
#![cfg(feature = "private-sparse")]
use anyhow::{ensure, Result};
use mongodb::bson::{doc, oid::ObjectId};
use porthub_agent::private_network::{
    controller::{self, Event},
    policy::Engine,
    sparse,
    sparse_dispatch::{Node, Routes},
};
use porthub_agent::private_profile::Profile;
use porthub_api::{config::Config, domain::workspaces::token_digest};
use porthub_mesh::Identity;
use porthub_network::tcp_stream;
use std::{net::Ipv4Addr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, watch, Mutex},
    task::JoinSet,
    time::{timeout, Duration},
};
use tokio_util::sync::CancellationToken;
mod support;
use support::Case;
const TOKEN: &str = "isolated-private-runtime-0123456789abcdef0123456789";
struct Peer {
    id: String,
    ip: Ipv4Addr,
    node: Node,
    handle: sparse::Handle,
    policy: Arc<Mutex<Engine>>,
}
#[allow(clippy::too_many_arguments)]
async fn events(
    mut events: mpsc::Receiver<Event>,
    own: Arc<Peer>,
    other: Arc<Peer>,
    kernel: tcp_stream::Handle,
    accepted: mpsc::Sender<tokio::io::DuplexStream>,
    stop: CancellationToken,
) -> Result<()> {
    let mut services = std::collections::HashSet::new();
    let mut tasks = JoinSet::new();
    let result=async{loop{tokio::select!{
        _=stop.cancelled()=>break,
        event=events.recv()=>{let Some(event)=event else{break};match event {
            event @ (Event::Snapshot(_)|Event::Pair(_))=>{
                let mut policy=own.policy.lock().await;
                let other=other.clone();
                own.node.install_control(event,&mut policy,|routes|async move{
                    // This attests only synthetic native-stack route preparation.
                    // It neither mutates an OS route nor waives an OS collision audit.
                    match routes {Routes::Base(base)=>ensure!(base.peers.len()==1&&base.sparse.is_some(),"sparse base disclosed an unbounded peer set"),Routes::Pair(pair)=>ensure!(pair.peer.id==other.id&&pair.peer.ip==other.ip,"pair route escaped exact requested identity"),Routes::Retire(peer)=>ensure!(peer.id==other.id,"denial retired foreign identity")};Ok(())
                }).await?;
            },
            Event::StreamDatagram{destination,payload,permit}=>{
                ensure!(destination==other.ip,"carrier escaped exact current pair IP");
                let wire=porthub_mesh::control_packet::encode(porthub_mesh::control_packet::STREAM,own.ip,destination,&payload)?;
                let packet=porthub_mesh::control_packet::decode(porthub_mesh::control_packet::STREAM,wire).ok_or_else(||anyhow::anyhow!("invalid carrier envelope"))?;
                let permit=permit.ok_or_else(||anyhow::anyhow!("carrier lost originating request"))?;
                if own.handle.by_id(&other.id).is_none()||!permit.valid(){continue;}
                permit.during(async{other.node.receive(&own.id,packet.source,packet.payload)}).await??;
            },
            Event::GuardedStreamLocal{peer,packet}=>{
                ensure!(peer==other.id,"native output escaped authenticated identity");
                if !own.policy.lock().await.check(packet.bytes(),&peer,true){continue;}
                ensure!(!own.node.raw_ingress(packet.bytes()),"optimized tuple also admitted raw transport");
                let syn=packet.bytes().get(33).is_some_and(|flags|flags&0x12==2);
                let flow=tcp_stream::Flow::from_packet(packet.bytes()).ok_or_else(||anyhow::anyhow!("native tuple absent"))?;
                if syn&&services.insert(flow){let kernel=kernel.clone();let ready=accepted.clone();tasks.spawn(async move{let(_,app)=packet.deliver(|bytes|async move{kernel.accept_syn(bytes).await}).await?;ready.send(app).await.map_err(|_|anyhow::anyhow!("service owner stopped"))});}
                else {let kernel=kernel.clone();packet.deliver(|bytes|async move{kernel.packet(bytes)}).await?;}
            },
            _=>{},
        }},
        result=tasks.join_next(),if !tasks.is_empty()=>{result.unwrap()??;}
    }}Ok::<_,anyhow::Error>(())}.await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}
#[tokio::test]
#[ignore = "requires one isolated MongoDB via PORTHUB_TEST_MONGO_URI; no native OS operations"]
async fn real_4097_registration_api_controller_to_autonomous_cross_pool_native_application_duplex(
) -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let stop = CancellationToken::new();
    let _guard = stop.clone().drop_guard();
    let mut tasks = JoinSet::new();
    let result=timeout(Duration::from_secs(45),async {
        let(owner,_)=case.user("sparse-runtime@test.invalid","user").await?;
        let mut ids=Vec::new();let mut machines=Vec::new();let mut peers=Vec::new();
        for i in 0..4097u32 {
            let machine=ObjectId::new();let id=format!("{owner}:{machine}");
            let ip=if i==4096 {Ipv4Addr::new(10,235,0,1)}else{Ipv4Addr::from(u32::from(Ipv4Addr::new(10,234,0,1))+i)};
            machines.push(doc!{"_id":machine,"user_id":owner,"name":format!("Private runtime {i}")});
            peers.push(doc!{"_id":&id,"workspace_id":owner,"machine_id":machine,"owner_id":owner,"ip":ip.to_string(),"enabled":true,"credential_hash":token_digest(TOKEN)});
            ids.push((id,ip));
        }
        case.app.collection("machines").insert_many(machines).await?;case.app.collection("private_peers").insert_many(peers).await?;
        case.app.collection("private_peers").create_index(mongodb::IndexModel::builder().keys(doc!{"workspace_id":1,"ip":1}).options(mongodb::options::IndexOptions::builder().unique(true).build()).build()).await?;
        let group=ObjectId::new();let book=ObjectId::new();
        case.app.collection("machine_groups").insert_one(doc!{"_id":group,"user_id":owner}).await?;
        case.app.collection("access_rulebooks").insert_one(doc!{"_id":book,"user_id":owner,"group_id":group.to_hex(),"revision":1_i64,"enabled":true,"rules":[{"id":"runtime443","name":"Exact native runtime service","sources":[{"kind":"all","id":"machines"}],"destinations":[{"kind":"all","id":"machines"}],"protocol":"tcp","ports":"443","bidirectional":false,"enabled":true}]}).await?;
        case.app.collection("private_networks").insert_one(doc!{"_id":owner.to_hex(),"cidr":"10.234.0.0/19","additional_cidrs":["10.235.0.0/19"],"dns_suffix":"phub"}).await?;
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;let router=case.router.clone();let done=stop.clone();
        tasks.spawn(async move{axum::serve(listener,router).with_graceful_shutdown(done.cancelled_owned()).await.map_err(Into::into)});
        let (ha,ca)=sparse::channel();let(hb,cb)=sparse::channel();let a_identity=Identity::new()?;let b_identity=Identity::new()?;
        let(aid,aip)=ids[0].clone();let(bid,bip)=ids[4096].clone();
        let(ea,ra)=mpsc::channel(64);let(eb,rb)=mpsc::channel(64);
        let(a,ar)=Node::new(owner.to_hex(),aid.clone(),a_identity.clone(),ha.clone(),ea.clone(),stop.child_token())?;
        let(b,br)=Node::new(owner.to_hex(),bid.clone(),b_identity.clone(),hb.clone(),eb.clone(),stop.child_token())?;
        let a=Arc::new(Peer{id:aid.clone(),ip:aip,node:a,handle:ha.clone(),policy:Arc::new(Mutex::new(Engine::default()))});
        let b=Arc::new(Peer{id:bid.clone(),ip:bip,node:b,handle:hb.clone(),policy:Arc::new(Mutex::new(Engine::default()))});
        tasks.spawn(ar.run());tasks.spawn(br.run());
        for(id,identity,control,events)in[(aid.clone(),a_identity,ca,ea),(bid.clone(),b_identity,cb,eb)]{
            let profile=Profile{server:format!("http://{address}"),peer_id:id.clone(),token:TOKEN.into(),workspace:owner.to_hex(),account_email:None,fallback_servers:vec![],allow_insecure_http_for_tests:true};
            let(_updates,interfaces)=watch::channel(vec![]);let(relay,_)=watch::channel(None);
            tasks.spawn(controller::run_watched_sparse(profile,interfaces,Default::default(),events,relay,controller::LocalIdentity{instance:format!("runtime-{}",&id[id.len()-16..]),certificate:identity},stop.child_token(),Some(control)));
        }
        let(ka,pa,kar)=tcp_stream::stack()?;let(kb,pb,kbr)=tcp_stream::stack()?;
        tasks.spawn(kar.run(stop.child_token()));tasks.spawn(kbr.run(stop.child_token()));
        let(accepted,mut apps)=mpsc::channel(2);
        tasks.spawn(events(ra,a.clone(),b.clone(),ka.clone(),accepted.clone(),stop.child_token()));
        tasks.spawn(events(rb,b.clone(),a.clone(),kb.clone(),accepted,stop.child_token()));
        for(own,other,mut packets)in[(a.clone(),b.clone(),pa),(b.clone(),a.clone(),pb)]{
            let cancel=stop.child_token();tasks.spawn(async move{loop{tokio::select!{_=cancel.cancelled()=>{while packets.recv().await.is_some(){}break;},packet=packets.recv()=>{let Some(packet)=packet else{break};if own.policy.lock().await.check(&packet,&other.id,false){ensure!(own.node.kernel_packet(&other.id,packet,true),"admitted native flow unexpectedly fell through raw path");}}}}Ok(())});
        }
        timeout(Duration::from_secs(20),async{loop{
            ha.request_peer(&bid);hb.request_peer(&aid);
            if ha.by_id(&bid).is_some()&&hb.by_id(&aid).is_some(){break;}
            if tasks.is_empty(){anyhow::bail!("private control owners stopped");}
            tokio::time::sleep(Duration::from_millis(20)).await;
        }Ok::<_,anyhow::Error>(())}).await??;
        ensure!(ha.peers().len()==1&&hb.peers().len()==1&&a.node.counts()==(0,0)&&b.node.counts()==(0,0),"4097 registrations allocated full-mesh flow resources");
        for id in [&aid,&bid] {let row=case.app.collection("private_peers").find_one(doc!{"_id":id}).await?.ok_or_else(||anyhow::anyhow!("controller publication absent"))?;ensure!(row.get_str("stream_transport").unwrap_or_default().is_empty(),"unproven native lifecycle unexpectedly advertised origin mode");}

        let started=std::time::Instant::now();let flow=tcp_stream::Flow{source:std::net::SocketAddrV4::new(aip,42000),destination:std::net::SocketAddrV4::new(bip,443)};
        let client=tokio::spawn(async move{ka.connect(flow).await});let mut server=apps.recv().await.ok_or_else(||anyhow::anyhow!("service never received authenticated native SYN"))?;let mut client=client.await??;
        let request=vec![0x35;8192*2+193];let answer=vec![0x79;8192*2+77];let expected=request.clone();let reply=answer.clone();
        let service=tokio::spawn(async move{let mut bytes=Vec::new();server.read_to_end(&mut bytes).await?;ensure!(bytes==expected,"API-authorized request mismatch");server.write_all(&reply).await?;server.shutdown().await?;Ok::<_,anyhow::Error>(())});
        client.write_all(&request).await?;client.shutdown().await?;let mut bytes=Vec::new();client.read_to_end(&mut bytes).await?;ensure!(bytes==answer,"API-authorized response mismatch");service.await??;
        ensure!(a.node.counts()==(1,2)&&b.node.counts()==(1,2),"cross-pool application exceeded actual bounded owner counts");
        println!("registered=4097 active_identity_pairs=1 source_flow_slots=2 destination_flow_slots=2 request_bytes={} response_bytes={} native_application_elapsed_ms={}",request.len(),answer.len(),started.elapsed().as_millis());
        let revoke_started=std::time::Instant::now();
        case.app.collection("access_rulebooks").update_one(doc!{"_id":book},doc!{"$set":{"enabled":false},"$inc":{"revision":1_i64}}).await?;
        ha.request_peer(&bid);hb.request_peer(&aid);
        timeout(Duration::from_secs(5),async {while a.node.counts()!=(0,0)||b.node.counts()!=(0,0){tokio::time::sleep(Duration::from_millis(10)).await;}}).await?;
        ensure!(a.policy.lock().await.valid_lease()&&b.policy.lock().await.valid_lease()&&ha.by_id(&bid).is_none()&&hb.by_id(&aid).is_none(),"real policy revoke retained pair or unnecessarily revoked still-valid base");
        println!("actual_rulebook_revoke_dispatch_retirement_ms={}",revoke_started.elapsed().as_millis());
        Ok::<_,anyhow::Error>((a,b))
    }).await;
    stop.cancel();
    let joined = timeout(Duration::from_secs(5), async {
        while let Some(task) = tasks.join_next().await {
            task??;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;
    if joined.is_err() {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    let dropped = case.db.drop().await;
    let (a, b) = result??;
    joined??;
    dropped?;
    ensure!(
        a.node.counts() == (0, 0) && b.node.counts() == (0, 0),
        "native/API dispatcher owner leak"
    );
    Ok(())
}
