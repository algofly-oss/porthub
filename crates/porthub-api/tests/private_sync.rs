use anyhow::{ensure, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use porthub_api::{
    config::Config,
    domain::{private_sync, workspaces::token_digest},
    private_transport::Settings,
};
use serde_json::{json, Value};
mod support;
use support::Case;

fn fingerprint(byte: &str) -> String {
    vec![byte; 32].join(":")
}
fn sync(id: &str, fp: &str, instance: &str) -> Value {
    json!({"peer_id":id,"token":"fixture-token-0123456789abcdef0123456789","fingerprint":fp,"instance":instance})
}
fn signal(to: &str, kind: &str, fp: &str) -> Value {
    json!({"to":to,"session":"session-0123456789","description":{"type":kind,"sdp":format!("v=0\r\na=fingerprint:sha-256 {fp}\r\n")}})
}
#[test]
fn sync_model_matches_original_client_messages_and_errors() {
    // The Python fixture predates the current trickle-candidate extension.
    // Its one enum-error expectation includes that existing third message type.
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/private-sync.json")).unwrap();
    for case in cases {
        let raw = serde_json::from_str(case["body"].as_str().unwrap()).unwrap();
        let actual = private_sync::parse(raw)
            .map(|v| serde_json::to_value(v).unwrap())
            .unwrap_or_else(|e| json!({"detail":e.detail}));
        assert_eq!(actual, case["response"], "{}", case["body"]);
    }
}
#[test]
fn candidate_signaling_checks_certificate_identity_even_with_identical_lan_hints() {
    let fp = fingerprint("AB");
    let mut body = sync("peer-0", &fp, "instance-00000000");
    let sdp = format!(
        "a=fingerprint:sha-256 {fp}\r\na=candidate:1 1 udp 10 192.168.1.5 9000 typ host\r\n"
    );
    body["signals"] = json!([{"to":"peer-1","session":"session-0123456789","description":{"type":"candidate","sdp":sdp}}]);
    let parsed = private_sync::parse(body.clone())
        .ok()
        .expect("valid fixture");
    let candidate = &parsed.signals[0];
    assert!(
        porthub_api::routes::private_sync::validate_signal("peer-0", "peer-1", candidate, &fp)
            .is_ok()
    );
    assert!(porthub_api::routes::private_sync::validate_signal(
        "peer-0",
        "peer-1",
        candidate,
        &fingerprint("CD")
    )
    .is_err());
    for invalid in [
        format!("{sdp}a=candidate:2 1 udp 9 192.168.1.5 9001 typ host\r\n"),
        format!("{sdp}a=fingerprint:sha-256 {}\r\n", fingerprint("CD")),
        "x".repeat(4097),
    ] {
        body["signals"][0]["description"]["sdp"] = json!(invalid);
        let parsed = private_sync::parse(body.clone())
            .ok()
            .expect("valid fixture");
        assert!(porthub_api::routes::private_sync::validate_signal(
            "peer-0",
            "peer-1",
            &parsed.signals[0],
            &fp
        )
        .is_err());
    }
}
#[test]
fn configured_ice_credentials_are_peer_scoped_and_routes_are_bounded() {
    let settings=Settings::parse(r#"[{"urls":["stun:example.test:3478"]},{"urls":["https://wrong.test"]},{"urls":[7]}]"#,
        "https://one.test/,https://user:secret@wrong.test,http://two.test,not-a-url,https://three.test,https://four.test,https://five.test",
        "0123456789abcdef0123456789abcdef");
    assert_eq!(settings.relay_routes.len(), 4);
    let ice = settings.ice("peer-id", 1_700_000_000);
    assert_eq!(ice.len(), 2);
    assert_eq!(ice[1]["username"], "1700043200:peer-id");
    assert_eq!(ice[1]["credential"], "qCXMIethb8oXJMk+UECxOO0Qtgs=");
    assert_ne!(
        ice[1]["credential"],
        settings.ice("another-peer", 1_700_000_000)[1]["credential"]
    );
    assert_eq!(Settings::default().ice("peer-id", 0), Vec::<Value>::new());
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn native_signaling_authenticates_identity_limits_discovery_and_binds_both_instances(
) -> Result<()> {
    let config = Config {
        tunnel_fallback_base_urls: vec!["https://fallback.test/api".into()],
        ..Default::default()
    };
    let case = Case::new(config).await?;
    let result=async {
        let (owner,_)=case.user("sync-owner@test.invalid","user").await?;
        let ids=[ObjectId::new(),ObjectId::new(),ObjectId::new()];
        let token="fixture-token-0123456789abcdef0123456789";
        for (i,mid) in ids.iter().enumerate() {
            case.app.collection("machines").insert_one(doc!{"_id":mid,"user_id":owner,"name":format!("Machine{i}"),"token":"never-return-public-token"}).await?;
            case.app.collection("private_peers").insert_one(doc!{"_id":format!("peer-{i}"),"workspace_id":owner,"machine_id":mid,"owner_id":owner,
                "ip":format!("10.203.0.{}",i+10),"enabled":true,"credential_hash":token_digest(token)}).await?;
        }
        let group=ObjectId::new();
        case.app.collection("machine_groups").insert_one(doc!{"_id":group,"user_id":owner}).await?;
        case.app.collection("access_rulebooks").insert_one(doc!{"_id":ObjectId::new(),"user_id":owner,"group_id":group.to_hex(),"rules":[{
            "id":"ssh","name":"SSH","sources":[{"kind":"machine","id":ids[0].to_hex()}],"destinations":[{"kind":"machine","id":ids[1].to_hex()}],"ports":"22"}]}).await?;
        let fp0=fingerprint("AB");let fp1=fingerprint("CD");
        let mut request0=sync("peer-0",&fp0,"instance-00000000");request0["stream_transport"]=json!("quic1");
        let request1=sync("peer-1",&fp1,"instance-11111111");
        let mut bad=request0.clone();bad["token"]=json!("wrong-token-0123456789abcdef0123456789");
        case.status("POST","/api/access/private/sync","",bad,StatusCode::FORBIDDEN).await?;
        case.status("POST","/api/access/private/sync","",request1.clone(),StatusCode::OK).await?;
        let (status,headers,initial)=case.call("POST","/api/access/private/sync","",request0.clone(),&[]).await?;
        ensure!(status==StatusCode::OK && headers["cache-control"]=="no-store");
        ensure!(initial["snapshot"]["self"]=="peer-0" && initial["snapshot"]["workspace"]==owner.to_hex());
        ensure!(initial["snapshot"]["peers"].as_array().unwrap().iter().any(|peer|peer["id"]=="peer-0" && peer["stream_transport"]=="quic1"));
        ensure!(initial["snapshot"]["peers"].as_array().unwrap().iter().any(|peer|peer["id"]=="peer-1" && peer["stream_transport"]==""));
        ensure!(chrono::DateTime::parse_from_rfc3339(initial["snapshot"]["expires_at"].as_str().unwrap()).is_ok());
        ensure!(initial["snapshot"]["peers"].as_array().unwrap().len()==2);
        ensure!(initial["snapshot"]["grants"][0]["source"]=="peer-0" && initial["snapshot"]["grants"][0]["destination"]=="peer-1");
        ensure!(initial["control_fallback_urls"]==json!(["https://fallback.test"]));
        let text=initial.to_string();for private in [token,"never-return-public-token","peer-2","credential_hash"] {ensure!(!text.contains(private));}
        let mut offer=request0.clone();offer["signals"]=json!([signal("peer-1","offer",&fp0),signal("peer-2","offer",&fp0)]);
        case.status("POST","/api/access/private/sync","",offer.clone(),StatusCode::OK).await?;
        case.status("POST","/api/access/private/sync","",offer.clone(),StatusCode::OK).await?;
        ensure!(case.app.collection("private_signals").count_documents(doc!{}).await?==1);
        let received=case.status("POST","/api/access/private/sync","",request1.clone(),StatusCode::OK).await?;
        ensure!(received["signals"].as_array().unwrap().len()==1 && received["signals"][0]["from"]=="peer-0");
        let message=received["signals"][0]["id"].as_str().unwrap().to_owned();
        let mut wrong_ack=request0.clone();wrong_ack["acks"]=json!([message]);
        case.status("POST","/api/access/private/sync","",wrong_ack,StatusCode::OK).await?;
        ensure!(case.app.collection("private_signals").count_documents(doc!{}).await?==1);
        let restarted=sync("peer-1",&fp1,"instance-22222222");
        ensure!(case.status("POST","/api/access/private/sync","",restarted.clone(),StatusCode::OK).await?["signals"]==json!([]));
        case.status("POST","/api/access/private/sync","",offer.clone(),StatusCode::OK).await?;
        let received=case.status("POST","/api/access/private/sync","",restarted.clone(),StatusCode::OK).await?;
        ensure!(received["signals"].as_array().unwrap().len()==1 && received["signals"][0]["id"]!=message);
        let mut ack=restarted.clone();ack["acks"]=json!([received["signals"][0]["id"]]);
        ensure!(case.status("POST","/api/access/private/sync","",ack,StatusCode::OK).await?["signals"]==json!([]));
        let mut forged=request0.clone();forged["signals"]=json!([signal("peer-1","offer",&fp1)]);
        case.status("POST","/api/access/private/sync","",forged,StatusCode::BAD_REQUEST).await?;
        let mut wrong_direction=restarted.clone();wrong_direction["signals"]=json!([signal("peer-0","offer",&fp1)]);
        case.status("POST","/api/access/private/sync","",wrong_direction,StatusCode::BAD_REQUEST).await?;
        // Certificate rotation in the same process also invalidates queued data.
        case.status("POST","/api/access/private/sync","",offer.clone(),StatusCode::OK).await?;
        let rotated=sync("peer-1",&fingerprint("EF"),"instance-22222222");
        ensure!(case.status("POST","/api/access/private/sync","",rotated.clone(),StatusCode::OK).await?["signals"]==json!([]));
        case.status("POST","/api/access/private/sync","",offer,StatusCode::OK).await?;
        ensure!(case.status("POST","/api/access/private/sync","",rotated.clone(),StatusCode::OK).await?["signals"].as_array().unwrap().len()==1);
        case.status("POST","/api/access/private/sync","",sync("peer-0",&fp0,"instance-33333333"),StatusCode::OK).await?;
        ensure!(case.status("POST","/api/access/private/sync","",rotated,StatusCode::OK).await?["signals"]==json!([]));
        case.app.collection("private_peers").update_one(doc!{"_id":"peer-0"},doc!{"$set":{"enabled":false}}).await?;
        case.status("POST","/api/access/private/sync","",request0,StatusCode::FORBIDDEN).await?;
        let survivor=case.status("POST","/api/access/private/sync","",restarted,StatusCode::OK).await?;
        ensure!(survivor["snapshot"]["peers"].as_array().unwrap().len()==1 && survivor["snapshot"]["grants"]==json!([]));
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn private_sync_denies_revoked_members_disabled_machines_and_expired_signaling() -> Result<()>
{
    let case = Case::new(Config::default()).await?;
    let result=async {
        let (owner,_)=case.user("sync-membership-owner@test.invalid","user").await?;
        let (member,_)=case.user("sync-membership-user@test.invalid","user").await?;
        let machine=ObjectId::new();let peer="member-peer";
        case.app.collection("machines").insert_one(doc!{"_id":machine,"user_id":member}).await?;
        case.app.collection("private_peers").insert_one(doc!{"_id":peer,"workspace_id":owner,"machine_id":machine,"owner_id":member,"enabled":true,
            "credential_hash":token_digest("fixture-token-0123456789abcdef0123456789"),"ip":"10.203.0.10"}).await?;
        let request=sync(peer,&fingerprint("AB"),"instance-00000000");
        case.status("POST","/api/access/private/sync","",request.clone(),StatusCode::FORBIDDEN).await?;
        case.app.collection("workspace_members").insert_one(doc!{"_id":format!("{owner}:{member}"),"workspace_id":owner,"user_id":member,"role":"member"}).await?;
        case.app.collection("private_signals").insert_one(doc!{"_id":"expired","from":peer,"to":peer,"source_instance":"instance-00000000","target_instance":"instance-00000000",
            "fingerprint":fingerprint("AB"),"target_fingerprint":fingerprint("AB"),"expires_at":DateTime::from_millis(1)}).await?;
        let response=case.status("POST","/api/access/private/sync","",request.clone(),StatusCode::OK).await?;
        ensure!(response["signals"]==json!([]));
        case.app.collection("machines").update_one(doc!{"_id":machine},doc!{"$set":{"enabled":false}}).await?;
        case.status("POST","/api/access/private/sync","",request.clone(),StatusCode::FORBIDDEN).await?;
        case.app.collection("machines").update_one(doc!{"_id":machine},doc!{"$set":{"enabled":true,"deletion_pending":true}}).await?;
        case.status("POST","/api/access/private/sync","",request.clone(),StatusCode::FORBIDDEN).await?;
        case.app.collection("machines").update_one(doc!{"_id":machine},doc!{"$unset":{"deletion_pending":""},"$set":{"private_owner_revoked":true}}).await?;
        case.status("POST","/api/access/private/sync","",request.clone(),StatusCode::FORBIDDEN).await?;
        case.app.collection("machines").update_one(doc!{"_id":machine},doc!{"$unset":{"private_owner_revoked":""}}).await?;
        case.app.collection("workspace_members").delete_one(doc!{"_id":format!("{owner}:{member}")}).await?;
        case.status("POST","/api/access/private/sync","",request,StatusCode::FORBIDDEN).await?;
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn exit_discovery_is_scoped_without_creating_private_port_grants() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result = async {
        let (owner, _) = case.user("exit-sync@test.invalid", "user").await?;
        let ids = [ObjectId::new(), ObjectId::new(), ObjectId::new(), ObjectId::new()];
        for (i, id) in ids.iter().enumerate() {
            case.app.collection("machines").insert_one(doc! {"_id":id,"user_id":owner,"name":format!("machine-{i}")}).await?;
            case.app.collection("private_peers").insert_one(doc! {"_id":format!("peer-{i}"),"workspace_id":owner,"machine_id":id,"owner_id":owner,"ip":format!("10.203.0.{}",i+10),"enabled":true,"credential_hash":token_digest("fixture-token-0123456789abcdef0123456789")}).await?;
        }
        case.app.collection("private_exit_nodes").insert_one(doc! {"_id":ObjectId::new(),"workspace_id":owner,"name":"Exits","enabled":true,"selection":"round_robin",
            "routing_selectors":[{"kind":"machine","id":ids[1].to_hex()},{"kind":"machine","id":ids[2].to_hex()}],
            "distribution_selectors":[{"kind":"machine","id":ids[0].to_hex()}]}).await?;
        for (i, peer_count, route_count) in [(0,3,1),(1,2,1),(2,2,1),(3,1,0)] {
            let response = case.status("POST", "/api/access/private/sync", "", sync(&format!("peer-{i}"), &fingerprint("AB"), "instance-00000000"), StatusCode::OK).await?;
            let snapshot = &response["snapshot"];
            ensure!(snapshot["peers"].as_array().unwrap().len() == peer_count, "peer {i}: {snapshot}");
            ensure!(snapshot["grants"].as_array().unwrap().is_empty());
            ensure!(snapshot["exit_routes"].as_array().unwrap().len() == route_count);
            if route_count > 0 {
                ensure!(snapshot["exit_routes"][0]["selection"] == "round_robin");
                let policy = serde_json::from_value(snapshot.clone())?;
                porthub_agent::private_network::policy::Engine::default().apply(policy)?;
            }
        }
        Ok::<_,anyhow::Error>(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn cross_pool_growth_keeps_legacy_sync_identity_acl_and_peer_ips() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result = async {
        let (owner, _) = case.user("cross-pool-owner@test.invalid", "user").await?;
        let (neighbor, _) = case.user("cross-pool-neighbor@test.invalid", "user").await?;
        case.app.collection("private_networks").insert_one(doc! {"_id":owner.to_hex(),"cidr":"10.222.0.0/28","dns_suffix":"phub"}).await?;
        case.app.collection("private_networks").insert_one(doc! {"_id":neighbor.to_hex(),"cidr":"10.222.0.16/28","dns_suffix":"internal"}).await?;
        let token = "fixture-token-0123456789abcdef0123456789";
        let mut old = Vec::new();
        let mut ids = Vec::new();
        for host in 1..=14 {
            let machine = ObjectId::new();
            let peer = format!("{owner}:{machine}");
            let ip = format!("10.222.0.{host}");
            case.app.collection("machines").insert_one(doc! {"_id":machine,"user_id":owner,"name":format!("Old machine {host}")}).await?;
            case.app.collection("private_peers").insert_one(doc! {"_id":&peer,"workspace_id":owner,"machine_id":machine,"owner_id":owner,"ip":&ip,"enabled":true,"credential_hash":token_digest(token)}).await?;
            old.push((peer, ip));
            ids.push(machine);
        }
        let joined = ObjectId::new();
        case.app.collection("machines").insert_one(doc! {"_id":joined,"user_id":owner,"name":"Overflow machine"}).await?;
        porthub_api::domain::enrollment::ensure(&case.app, &doc! {"_id":joined,"user_id":owner}).await.map_err(|e| anyhow::anyhow!("{}", e.detail))?;
        let destination = format!("{owner}:{joined}");
        case.app.collection("private_peers").update_one(doc! {"_id":&destination},doc! {"$set":{"credential_hash":token_digest(token)}}).await?;
        let added = case.app.collection("private_peers").find_one(doc! {"_id":&destination}).await?.unwrap();
        let added_ip = added.get_str("ip")?.to_owned();
        ensure!(!porthub_api::domain::enrollment::Network::parse("10.222.0.0/28").unwrap().contains(added_ip.parse()?));
        let group = ObjectId::new();
        case.app.collection("machine_groups").insert_one(doc! {"_id":group,"user_id":owner}).await?;
        case.app.collection("access_rulebooks").insert_one(doc! {"_id":ObjectId::new(),"user_id":owner,"group_id":group.to_hex(),"rules":[{"id":"cross-pool-https","name":"Cross-pool HTTPS","sources":[{"kind":"machine","id":ids[0].to_hex()}],"destinations":[{"kind":"machine","id":joined.to_hex()}],"ports":"443"}]}).await?;
        // Original client request shape has no pool/network extension fields.
        let request_b = sync(&destination, &fingerprint("CD"), "instance-11111111");
        let b = case.status("POST", "/api/access/private/sync", "", request_b, StatusCode::OK).await?;
        let a = case.status("POST", "/api/access/private/sync", "", sync(&old[0].0, &fingerprint("AB"), "instance-00000000"), StatusCode::OK).await?;
        let denied = case.status("POST", "/api/access/private/sync", "", sync(&old[1].0, &fingerprint("EF"), "instance-22222222"), StatusCode::OK).await?;
        let snapshot = &a["snapshot"];
        ensure!(snapshot["peers"].as_array().unwrap().len() == 2);
        ensure!(snapshot["peers"].as_array().unwrap().iter().any(|p| p["id"] == destination && p["ip"] == added_ip));
        ensure!(snapshot["peers"].as_array().unwrap().iter().any(|p| p["id"] == old[0].0 && p["ip"] == old[0].1));
        ensure!(snapshot["grants"].as_array().unwrap().len() == 1);
        ensure!(snapshot["grants"][0]["source"] == old[0].0 && snapshot["grants"][0]["destination"] == destination);
        ensure!(snapshot.get("cidrs").is_none() && snapshot.get("additional_cidrs").is_none());
        ensure!(denied["snapshot"]["peers"].as_array().unwrap().len() == 1 && denied["snapshot"]["grants"] == json!([]));
        // Apply the actual gateway snapshots to the existing packet policy:
        // CIDR boundaries grant nothing, and /32 identity bindings still govern.
        fn syn(source: &str, destination: &str, port: u16) -> Vec<u8> {
            let mut p = vec![0u8; 40];
            p[0] = 0x45; p[2..4].copy_from_slice(&40u16.to_be_bytes()); p[8] = 64; p[9] = 6;
            p[12..16].copy_from_slice(&source.parse::<std::net::Ipv4Addr>().unwrap().octets());
            p[16..20].copy_from_slice(&destination.parse::<std::net::Ipv4Addr>().unwrap().octets());
            p[20..22].copy_from_slice(&32123u16.to_be_bytes()); p[22..24].copy_from_slice(&port.to_be_bytes()); p[32] = 0x50; p[33] = 2;
            let mut sum: u32 = p[..20].chunks_exact(2).map(|b| u32::from(u16::from_be_bytes([b[0],b[1]]))).sum();
            while sum >> 16 != 0 { sum = (sum & 65535) + (sum >> 16); }
            p[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes()); p
        }
        let mut source_policy = porthub_agent::private_network::policy::Engine::default();
        source_policy.apply(serde_json::from_value(snapshot.clone())?)?;
        let mut destination_policy = porthub_agent::private_network::policy::Engine::default();
        destination_policy.apply(serde_json::from_value(b["snapshot"].clone())?)?;
        ensure!(source_policy.check(&syn(&old[0].1, &added_ip, 443), &destination, false));
        ensure!(destination_policy.check(&syn(&old[0].1, &added_ip, 443), &old[0].0, true));
        ensure!(!source_policy.check(&syn(&old[0].1, &added_ip, 22), &destination, false));
        ensure!(!source_policy.check(&syn(&old[0].1, &old[1].1, 443), &old[1].0, false));
        ensure!(!destination_policy.check(&syn(&old[1].1, &added_ip, 443), &old[0].0, true), "A denied peer cannot spoof an allowed identity across pools");
        for (peer, ip) in old {
            let row = case.app.collection("private_peers").find_one(doc! {"_id":peer}).await?.unwrap();
            ensure!(row.get_str("ip")? == ip && row.get_str("credential_hash")? == token_digest(token) && row.get_bool("enabled")?);
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    case.db.drop().await?;
    result
}

#[cfg(feature="private-sparse")]
#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn sparse_4097_broad_peers_return_bounded_pair_authority_and_legacy_fails_actionably()->Result<()> {
    let case=Case::new(Config::default()).await?;
    let result=async {
        let (owner,_)=case.user("sparse-owner@test.invalid","user").await?;
        let token="fixture-token-0123456789abcdef0123456789";
        let mut machines=Vec::new();let mut peers=Vec::new();
        for i in 0..4097u32 {
            let mid=ObjectId::new();let ip=std::net::Ipv4Addr::from(u32::from(std::net::Ipv4Addr::new(10,203,0,1))+i);
            machines.push(doc!{"_id":mid,"user_id":owner,"name":format!("Sparse{i}")});
            peers.push(doc!{"_id":format!("sparse-{i}"),"workspace_id":owner,"machine_id":mid,"owner_id":owner,"ip":ip.to_string(),"enabled":true,"credential_hash":token_digest(token)});
        }
        case.app.collection("machines").insert_many(machines).await?;case.app.collection("private_peers").insert_many(peers).await?;
        case.app.collection("private_peers").create_index(mongodb::IndexModel::builder().keys(doc!{"workspace_id":1,"ip":1}).options(mongodb::options::IndexOptions::builder().unique(true).build()).build()).await?;
        let group=ObjectId::new();case.app.collection("machine_groups").insert_one(doc!{"_id":group,"user_id":owner}).await?;
        let book=ObjectId::new();case.app.collection("access_rulebooks").insert_one(doc!{"_id":book,"user_id":owner,"group_id":group.to_hex(),"revision":1_i64,"enabled":true,"updated_at":DateTime::now(),"rules":[{"id":"broad","name":"Broad private fixture","sources":[{"kind":"all","id":"machines"}],"destinations":[{"kind":"all","id":"machines"}],"protocol":"any","ports":"","bidirectional":true,"enabled":true}]}).await?;
        case.app.collection("private_networks").insert_one(doc!{"_id":owner.to_hex(),"cidr":"10.203.0.0/19","dns_suffix":"phub"}).await?;
        let make=|id:&str,instance:&str,sequence:u64|{let fp=if id=="sparse-0"{"AB"}else if id=="sparse-4096"{"CD"}else{"EF"};let mut body=sync(id,&fingerprint(fp),instance);body["sparse"]=json!({"protocol":1,"sequence":sequence,"wanted":[]});body};
        let mut a=make("sparse-0","instance-00000000",1);let b=make("sparse-4096","instance-11111111",1);
        let (_,_,first)=case.call("POST","/api/access/private/sync","",a.clone(),&[]).await?;
        ensure!(first["snapshot"]["peers"].as_array().is_some_and(|p|p.len()==1),"sparse base was not bounded");
        case.status("POST","/api/access/private/sync","",b,StatusCode::OK).await?;
        a["sparse"]["sequence"]=json!(2);a["sparse"]["wanted"]=json!([{"kind":"ip","value":"10.203.16.1"}]);
        case.db.run_command(doc!{"profile":2}).await?;
        let measured_start=DateTime::now();
        let measured=case.call("POST","/api/access/private/sync","",a.clone(),&[]).await;
        case.db.run_command(doc!{"profile":0}).await?;
        let (status,_,reply)=measured?;ensure!(status==StatusCode::OK,"sparse pair request failed");
        let broad_cost=sparse_profile_cost(&case,measured_start).await?;
        ensure!(broad_cost["docs_examined"].as_i64().unwrap_or(i64::MAX)<128,"broad sparse lookup scanned registration population: {broad_cost}");
        println!("sparse4097_broad_cost={broad_cost}");
        ensure!(reply["pair_responses"][0]["status"]=="allowed","sparse pair was not allowed");
        let base:porthub_agent::private_network::policy::Snapshot=serde_json::from_value(reply["snapshot"].clone())?;
        let pair:porthub_network::policy::PairLease=serde_json::from_value(reply["pair_responses"][0]["lease"].clone())?;
        let mut engine=porthub_network::policy::Engine::default();engine.apply(base)?;engine.install_pair(pair)?;
        ensure!(engine.pair_count()==1 && serde_json::to_vec(&reply)?.len()<16384,"pair wire exceeded fixture byte budget");
        // Representative large explicit group: members are per-machine group_ids, not a
        // huge list fetched/scanned for every caller. Book selectors reference one group.
        case.app.collection("machines").update_many(doc!{"user_id":owner},doc!{"$set":{"group_ids":[group]}}).await?;
        let mut member_ids=(0..4096).map(|_|ObjectId::new()).collect::<Vec<_>>();member_ids.push(owner);
        case.app.collection("users").insert_many(member_ids.iter().take(4096).map(|id|doc!{"_id":id,"role":"user","name":"private fixture member"})).await?;
        case.app.collection("workspace_members").insert_many(member_ids.iter().take(4096).map(|id|doc!{"_id":ObjectId::new(),"workspace_id":owner,"user_id":id,"role":"member"})).await?;
        case.app.collection("machine_groups").update_one(doc!{"_id":group},doc!{"$set":{"user_ids":&member_ids}}).await?;
        case.app.collection("access_rulebooks").update_one(doc!{"_id":book},doc!{"$set":{"rules":[{"id":"group","name":"Explicit group fixture","sources":[{"kind":"group","id":group.to_hex()}],"destinations":[{"kind":"group","id":group.to_hex()}],"protocol":"tcp","ports":"443","bidirectional":true,"enabled":true}]},"$inc":{"revision":1_i64}}).await?;
        // Warm each local authority and immutable rule index once after the real policy edit.
        let b=make("sparse-4096","instance-11111111",2);case.status("POST","/api/access/private/sync","",b.clone(),StatusCode::OK).await?;
        a["sparse"]["sequence"]=json!(3);case.status("POST","/api/access/private/sync","",a.clone(),StatusCode::OK).await?;
        case.db.run_command(doc!{"profile":2}).await?;let measured_start=DateTime::now();
        a["sparse"]["sequence"]=json!(4);let measured=case.call("POST","/api/access/private/sync","",a.clone(),&[]).await;case.db.run_command(doc!{"profile":0}).await?;
        let (status,_,group_reply)=measured?;ensure!(status==StatusCode::OK&&group_reply["pair_responses"][0]["status"]=="allowed","explicit group sparse lease failed");
        let group_cost=sparse_profile_cost(&case,measured_start).await?;ensure!(group_cost["docs_examined"].as_i64().unwrap_or(i64::MAX)<128,"explicit membership lookup scanned population: {group_cost}");
        ensure!(group_cost["collections"]["machine_groups"]["docs_examined"]==0 && group_cost["collections"]["access_rulebooks"]["docs_examined"]==0,"policy metadata fetch was not covered: {group_cost}");
        println!("sparse4097_explicit_group_cost={group_cost}");
        let legacy=sync("sparse-1",&fingerprint("CD"),"instance-22222222");
        let (status,_,error)=case.call("POST","/api/access/private/sync","",legacy,&[]).await?;ensure!(status==StatusCode::BAD_REQUEST && error.to_string().contains("upgrade"),"legacy capacity failure not actionable (status {status})");
        // A target-only user-group removal changes B's authority, not A's base epoch.
        // The exact authenticated denial must still retire A's installed pair immediately.
        let target=case.app.collection("private_peers").find_one(doc!{"_id":"sparse-4096"}).await?.unwrap();
        let target_machine=target.get_object_id("machine_id")?;let member=member_ids[0];
        let source=case.app.collection("private_peers").find_one(doc!{"_id":"sparse-0"}).await?.unwrap();
        case.app.collection("machines").update_many(doc!{"_id":{"$in":[target_machine,source.get_object_id("machine_id")?]}},doc!{"$unset":{"group_ids":"","group_id":""}}).await?;
        case.app.collection("machines").update_one(doc!{"_id":target_machine},doc!{"$set":{"user_id":member}}).await?;
        case.app.collection("private_peers").update_one(doc!{"_id":"sparse-4096"},doc!{"$set":{"owner_id":member}}).await?;
        case.status("POST","/api/access/private/sync","",make("sparse-4096","instance-11111111",3),StatusCode::OK).await?;
        case.status("POST","/api/access/private/sync","",make("sparse-2","instance-33333333",1),StatusCode::OK).await?;
        a["sparse"]["wanted"].as_array_mut().unwrap().push(json!({"kind":"ip","value":"10.203.0.3"}));
        a["sparse"]["sequence"]=json!(5);let (_,_,member_reply)=case.call("POST","/api/access/private/sync","",a.clone(),&[]).await?;
        ensure!(member_reply["pair_responses"][0]["status"]=="allowed","cross-owner group member was not allowed");
        let authority:porthub_network::policy::Snapshot=serde_json::from_value(member_reply["snapshot"].clone())?;
        let lease:porthub_network::policy::PairLease=serde_json::from_value(member_reply["pair_responses"][0]["lease"].clone())?;
        let (handle,_)=porthub_agent::private_network::sparse::channel();handle.update_base(&authority);
        let mut policy=porthub_network::policy::Engine::default();policy.apply(authority)?;policy.install_pair(lease.clone())?;
        handle.installed(&porthub_network::policy::Lookup{kind:"ip".into(),value:"10.203.16.1".into()},lease);
        let other:porthub_network::policy::PairLease=serde_json::from_value(member_reply["pair_responses"][1]["lease"].clone())?;
        policy.install_pair(other.clone())?;handle.installed(&porthub_network::policy::Lookup{kind:"ip".into(),value:"10.203.0.3".into()},other);
        case.app.collection("machine_groups").update_one(doc!{"_id":group},doc!{"$pull":{"user_ids":member}}).await?;
        a["sparse"]["sequence"]=json!(6);let (_,_,denied)=case.call("POST","/api/access/private/sync","",a.clone(),&[]).await?;
        ensure!(denied["snapshot"]["sparse"]["epoch"]==member_reply["snapshot"]["sparse"]["epoch"],"unrelated local authority unexpectedly changed");
        let denial:porthub_network::policy::PairResponse=serde_json::from_value(denied["pair_responses"][0].clone())?;
        ensure!(denial.status=="unavailable"&&porthub_agent::private_network::sparse::apply_denial(&handle,&mut policy,&denial).is_some(),"fresh target-member denial did not retire its own pair");
        ensure!(policy.valid_lease()&&policy.pair_peer("sparse-4096").is_none()&&policy.pair_peer("sparse-2").is_some(),"target denial incorrectly revoked base or retained pair");
        // Membership denial of the SOURCE is a whole-enrollment rejection, not a pair miss.
        let (status,_,_)=case.call("POST","/api/access/private/sync","",b.clone(),&[]).await?;
        ensure!(status==StatusCode::OK,"current member source could not synchronize");
        case.app.collection("workspace_members").delete_one(doc!{"workspace_id":owner,"user_id":member}).await?;
        let (status,_,_)=case.call("POST","/api/access/private/sync","",b.clone(),&[]).await?;
        ensure!(status==StatusCode::FORBIDDEN,"removed source membership was not rejected authoritatively");
        case.app.collection("access_rulebooks").update_one(doc!{"_id":book},doc!{"$set":{"enabled":false}}).await?;
        a["sparse"]["sequence"]=json!(7);let (_,_,revoked)=case.call("POST","/api/access/private/sync","",a,&[]).await?;
        ensure!(revoked["snapshot"]["sparse"]["epoch"]!=denied["snapshot"]["sparse"]["epoch"],"policy generation did not change");
        ensure!(revoked["pair_responses"][0]["status"]=="unavailable"&&revoked["pair_responses"][1]["status"]=="unavailable","revoked pair remained allowed");
        Ok::<_,anyhow::Error>(())
    }.await;let _=case.db.drop().await;result
}

#[cfg(feature="private-sparse")]
async fn sparse_profile_cost(case:&Case,start:DateTime)->Result<Value>{
 use futures_util::TryStreamExt;
 let rows:Vec<mongodb::bson::Document>=case.db.collection("system.profile").find(doc!{"ts":{"$gte":start}}).projection(doc!{"ns":1,"docsExamined":1,"keysExamined":1,"responseLength":1,"nreturned":1}).limit(1024).await?.try_collect().await?;
 let mut docs=0i64;let mut keys=0i64;let mut bytes=0i64;let mut calls=0usize;let mut collections=std::collections::BTreeMap::<String,Value>::new();
 for row in rows{let ns=row.get_str("ns").unwrap_or_default();if ns.ends_with(".system.profile"){continue;}let read=|key|row.get_i64(key).ok().or_else(||row.get_i32(key).ok().map(i64::from)).unwrap_or(0);docs+=read("docsExamined");keys+=read("keysExamined");bytes+=read("responseLength");calls+=1;let collection=collections.entry(ns.split('.').skip(1).collect::<Vec<_>>().join(".")).or_insert(json!({"commands":0,"docs_examined":0,"keys_examined":0,"bytes":0}));
  for (key,delta) in [("commands",1),("docs_examined",read("docsExamined")),("keys_examined",read("keysExamined")),("bytes",read("responseLength"))]{collection[key]=json!(collection[key].as_i64().unwrap()+delta);}}
 Ok(json!({"registered":4097,"commands":calls,"docs_examined":docs,"keys_examined":keys,"response_bytes":bytes,"collections":collections}))
}
