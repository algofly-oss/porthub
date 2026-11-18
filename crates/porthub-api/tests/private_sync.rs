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
        let (owner,cookie)=case.user("sparse-owner@test.invalid","user").await?;
        let token="fixture-token-0123456789abcdef0123456789";
        let mut machines=Vec::new();let mut peers=Vec::new();
        for i in 0..4097u32 {
            let mid=ObjectId::new();let ip=std::net::Ipv4Addr::from(u32::from(std::net::Ipv4Addr::new(10,203,0,1))+i);
            let mut machine=doc!{"_id":mid,"user_id":owner,"name":format!("Sparse{i}")};
            if i==4096 {machine.insert("private_domains",vec![doc!{"default":true},doc!{"host":"cold","suffix":"custom.internal","default":false}]);}
            machines.push(machine);
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
        ensure!(first["snapshot"]["dns_suffixes"].as_array().is_some_and(|s|s.iter().any(|v|v=="custom.internal")),"cold peer's custom namespace was not protected before pair discovery");
        let cold=case.app.collection("private_peers").find_one(doc!{"_id":"sparse-4096"}).await?.unwrap().get_object_id("machine_id")?;
        case.status("PUT","/api/machines/update",&cookie,json!({"data_id":cold.to_hex(),"name":"Sparse4096","private_domains":[{"default":true},{"host":"cold","suffix":"custom.internal"},{"host":"fresh","suffix":"new.private.example"}]}),StatusCode::OK).await?;
        let (_,_,fresh_namespace)=case.call("POST","/api/access/private/sync","",a.clone(),&[]).await?;
        ensure!(fresh_namespace["snapshot"]["dns_suffixes"].as_array().is_some_and(|s|s.iter().any(|v|v=="new.private.example")),"native machine update did not invalidate cold namespace metadata immediately");
        ensure!(fresh_namespace["snapshot"]["peers"].as_array().is_some_and(|p|p.len()==1),"suffix-only update disclosed cold peer identities");

        case.status("POST","/api/access/private/sync","",b,StatusCode::OK).await?;
        let mut custom=a.clone();custom["sparse"]["wanted"]=json!([{"kind":"name","value":"fresh.new.private.example"}]);
        let (status,_,custom)=case.call("POST","/api/access/private/sync","",custom,&[]).await?;
        ensure!(status==StatusCode::OK&&custom["pair_responses"][0]["status"]=="allowed"&&custom["pair_responses"][0]["lease"]["peer"]["id"]=="sparse-4096","cold custom namespace name did not resolve through exact private pair authority");
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
        // A policy larger than the legacy pair grant bound must remain exact and
        // usable through fixed-size masks, never a truncated or invented denial.
        let complex:Vec<_>=(0..100).map(|i|doc!{"id":format!("port{i}"),"name":format!("Port{i}"),"sources":[{"kind":"all","id":"machines"}],"destinations":[{"kind":"all","id":"machines"}],"protocol":"tcp","ports":(1000+i).to_string(),"bidirectional":true,"enabled":true}).collect();
        case.app.collection("access_rulebooks").update_one(doc!{"_id":book},doc!{"$set":{"rules":complex},"$inc":{"revision":1_i64}}).await?;
        a["sparse"]["sequence"]=json!(7);let (_,_,cold_policy)=case.call("POST","/api/access/private/sync","",a.clone(),&[]).await?;
        ensure!(cold_policy["pair_responses"][1]["status"]=="busy","old target policy epoch incorrectly acknowledged the new complex policy");
        case.status("POST","/api/access/private/sync","",make("sparse-2","instance-33333333",2),StatusCode::OK).await?;
        a["sparse"]["sequence"]=json!(8);let (_,_,capacity)=case.call("POST","/api/access/private/sync","",a.clone(),&[]).await?;
        ensure!(capacity["pair_responses"][1]["status"]=="allowed"&&capacity["pair_responses"][1]["lease"]["acl"].is_object()&&capacity["pair_responses"][1]["lease"]["grants"]==json!([]),"complex allowed policy was denied or legacy grants were partially transmitted");
        let compact_base=serde_json::from_value(capacity["snapshot"].clone())?;
        let compact_lease=serde_json::from_value(capacity["pair_responses"][1]["lease"].clone())?;
        let mut compact_engine=porthub_network::policy::Engine::default();compact_engine.apply(compact_base)?;compact_engine.install_pair(compact_lease)?;
        ensure!(compact_engine.pair_count()==1&&serde_json::to_vec(&capacity)?.len()<65536,"compact complex authority exceeded its bounded representation");
        case.app.collection("access_rulebooks").update_one(doc!{"_id":book},doc!{"$set":{"enabled":false},"$inc":{"revision":1_i64}}).await?;
        a["sparse"]["sequence"]=json!(9);let (_,_,revoked)=case.call("POST","/api/access/private/sync","",a,&[]).await?;
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

#[cfg(feature="private-sparse")]
#[tokio::test]
#[ignore="requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn canonical_enrollment_ids_allow_cold_peer_lookup_but_never_foreign_workspace_authority()->Result<()> {
    let case=Case::new(Config::default()).await?;
    let result=async {
        let (owner,_)=case.user("canonical-owner@test.invalid","user").await?;
        let (foreign,_)=case.user("canonical-foreign@test.invalid","user").await?;
        let mut ids=Vec::new();let mut machines=Vec::new();
        for (i,workspace) in [owner,owner,foreign].into_iter().enumerate() {
            let machine=ObjectId::new();let id=format!("{workspace}:{machine}");
            case.app.collection("machines").insert_one(doc!{"_id":machine,"user_id":workspace,"name":format!("Canonical fixture {i}")}).await?;
            case.app.collection("private_peers").insert_one(doc!{"_id":&id,"workspace_id":workspace,"owner_id":workspace,"machine_id":machine,"ip":format!("10.203.0.{}",if i==2 {2}else{i+1}),"enabled":true,"credential_hash":token_digest("fixture-token-0123456789abcdef0123456789")}).await?;
            ids.push(id);machines.push(machine);
        }
        // Broad workspace destination rule and identical legacy-overlap IP/token
        // values ensure tenant identity, not an accidental selector mismatch,
        // is what rejects the foreign canonical ID.
        let group=ObjectId::new();case.app.collection("machine_groups").insert_one(doc!{"_id":group,"user_id":owner}).await?;
        case.app.collection("access_rulebooks").insert_one(doc!{"_id":ObjectId::new(),"user_id":owner,"group_id":group.to_hex(),"revision":1_i64,"enabled":true,"updated_at":DateTime::now(),"rules":[{"id":"canonical-https","name":"Workspace fixture HTTPS","sources":[{"kind":"machine","id":machines[0].to_hex()}],"destinations":[{"kind":"all","id":"machines"}],"ports":"443"}]}).await?;
        let make=|index:usize,sequence:u64|{let mut body=sync(&ids[index],&fingerprint(if index==0{"AB"}else{"CD"}),if index==0{"instance-00000000"}else{"instance-11111111"});body["sparse"]=json!({"protocol":1,"sequence":sequence,"wanted":[]});body};
        case.status("POST","/api/access/private/sync","",make(1,1),StatusCode::OK).await?;
        case.status("POST","/api/access/private/sync","",make(2,1),StatusCode::OK).await?;
        let mut own=make(0,1);own["sparse"]["wanted"]=json!([{"kind":"peer","value":ids[1]}]);
        let (status,_,reply)=case.call("POST","/api/access/private/sync","",own,&[]).await?;
        ensure!(status==StatusCode::OK,"canonical peer ID was rejected before authorization");
        ensure!(reply["pair_responses"][0]["status"]=="allowed"&&reply["pair_responses"][0]["lease"]["peer"]["id"]==ids[1],"canonical cold peer lookup did not publish exact own authorized identity");
        // Resolver renewal uses the peer ID returned inside the lease, even
        // when its initial admission was triggered through another lookup form.
        let returned_id=reply["pair_responses"][0]["lease"]["peer"]["id"].as_str().unwrap().to_owned();
        let mut renewal=make(0,2);renewal["sparse"]["wanted"]=json!([{"kind":"peer","value":returned_id}]);
        let (status,_,renewed)=case.call("POST","/api/access/private/sync","",renewal,&[]).await?;
        ensure!(status==StatusCode::OK&&renewed["pair_responses"][0]["status"]=="allowed","real enrolled ID returned in lease could not renew");
        let mut denied=make(0,3);denied["sparse"]["wanted"]=json!([{"kind":"peer","value":ids[2]}]);
        let (status,_,reply)=case.call("POST","/api/access/private/sync","",denied,&[]).await?;
        ensure!(status==StatusCode::OK,"foreign canonical query was not handled as a scoped lookup");
        ensure!(reply["pair_responses"][0]["status"]!="allowed"&&reply["pair_responses"][0].get("lease").is_none(),"syntactically valid foreign workspace ID bypassed authorization");
        // Membership in the same workspace is not itself an implicit port grant.
        case.app.collection("access_rulebooks").update_many(doc!{"user_id":owner},doc!{"$set":{"enabled":false},"$inc":{"revision":1_i64}}).await?;
        let mut no_rule=make(0,4);no_rule["sparse"]["wanted"]=json!([{"kind":"peer","value":ids[1]}]);
        let (status,_,reply)=case.call("POST","/api/access/private/sync","",no_rule,&[]).await?;
        ensure!(status==StatusCode::OK&&reply["pair_responses"][0]["status"]!="allowed"&&reply["pair_responses"][0].get("lease").is_none(),"canonical syntax became implicit ACL allow after rule revocation");
        Ok::<_,anyhow::Error>(())
    }.await;
    case.db.drop().await?;result
}

#[cfg(feature="private-sparse")]
#[tokio::test]
#[ignore="requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn unrelated_exit_plans_do_not_cap_sparse_fleets_but_participants_keep_complete_plans()->Result<()> {
 let case=Case::new(Config::default()).await?;
 let result=async {
  let (owner,_)=case.user("sparse-exit-isolation@test.invalid","user").await?;
  let (foreign,_)=case.user("sparse-exit-foreign@test.invalid","user").await?;
  let token="fixture-token-0123456789abcdef0123456789";
  let ids:Vec<_>=(0..4097).map(|_|ObjectId::new()).collect();
  let machines:Vec<_>=ids.iter().enumerate().map(|(i,id)|doc!{"_id":id,"user_id":owner,"name":format!("ExitSparse{i}")}).collect();
  let peers:Vec<_>=ids.iter().enumerate().map(|(i,id)|doc!{"_id":format!("exit-sparse-{i}"),"workspace_id":owner,"machine_id":id,"owner_id":owner,"ip":std::net::Ipv4Addr::from(u32::from(std::net::Ipv4Addr::new(10,210,0,1))+i as u32).to_string(),"enabled":true,"credential_hash":token_digest(token)}).collect();
  case.app.collection("machines").insert_many(machines).await?;
  case.app.collection("private_peers").insert_many(peers).await?;
  case.app.collection("private_networks").insert_one(doc!{"_id":owner.to_hex(),"cidr":"10.210.0.0/19","dns_suffix":"phub"}).await?;
  let group=ObjectId::new();
  case.app.collection("machine_groups").insert_one(doc!{"_id":group,"user_id":owner}).await?;
  case.app.collection("access_rulebooks").insert_one(doc!{"_id":ObjectId::new(),"user_id":owner,"group_id":group.to_hex(),"revision":1_i64,"enabled":true,"rules":[{"id":"all","name":"Private reachability","sources":[{"kind":"all","id":"machines"}],"destinations":[{"kind":"all","id":"machines"}],"protocol":"any","ports":"","bidirectional":true,"enabled":true}]}).await?;
  let route=ObjectId::new();
  case.app.collection("private_exit_nodes").insert_one(doc!{"_id":route,"workspace_id":owner,"enabled":true,"name":"Other machines' exit","routing_selectors":[{"kind":"machine","id":ids[1].to_hex()}],"distribution_selectors":[{"kind":"machine","id":ids[2].to_hex()}]}).await?;
  // An identically named/selected exit in another tenant is never authoritative.
  case.app.collection("private_exit_nodes").insert_one(doc!{"_id":ObjectId::new(),"workspace_id":foreign,"enabled":true,"routing_selectors":[{"kind":"machine","id":ids[0].to_hex()}],"distribution_selectors":[{"kind":"machine","id":ids[4096].to_hex()}]}).await?;
  let request=|id:&str,fp:&str,wanted:Value|{let mut b=sync(id,&fingerprint(fp),"instance-exit-0000");b["sparse"]=json!({"protocol":1,"sequence":1,"wanted":wanted});b};
  let receiver=request("exit-sparse-4096","CD",json!([]));
  case.status("POST","/api/access/private/sync","",receiver,StatusCode::OK).await?;
  let sender=request("exit-sparse-0","AB",json!([{"kind":"peer","value":"exit-sparse-4096"}]));
  let first=case.status("POST","/api/access/private/sync","",sender.clone(),StatusCode::OK).await?;
  ensure!(first["snapshot"]["sparse"]["protocol"]==1&&first["snapshot"]["peers"].as_array().unwrap().len()==1,"unrelated enabled exit restored whole-fleet policy");
  ensure!(first["snapshot"]["exit_routes"]==json!([])&&first["pair_responses"][0]["status"]=="allowed","private ACL was lost or unrelated exit disclosed");
  let first_epoch=first["snapshot"]["sparse"]["epoch"].clone();
  // Current group assignment, not an old directory/lease, determines participation.
  case.app.collection("private_exit_nodes").update_one(doc!{"_id":route},doc!{"$set":{"distribution_selectors":[{"kind":"group","id":group.to_hex()}]}}).await?;
  let still=case.status("POST","/api/access/private/sync","",sender.clone(),StatusCode::OK).await?;
  ensure!(still["snapshot"]["sparse"]["protocol"]==1,"unselected group changed authority mode");
  case.app.collection("machines").update_one(doc!{"_id":ids[0]},doc!{"$set":{"group_ids":[group]}}).await?;
  let (status,_,denied)=case.call("POST","/api/access/private/sync","",sender.clone(),&[]).await?;
  ensure!(status==StatusCode::BAD_REQUEST&&denied.to_string().contains("upgrade"),"participating group was silently given incomplete exit policy: {denied}");
  case.app.collection("machines").update_one(doc!{"_id":ids[0]},doc!{"$unset":{"group_ids":""}}).await?;
  let restored=case.status("POST","/api/access/private/sync","",sender.clone(),StatusCode::OK).await?;
  ensure!(restored["snapshot"]["sparse"]["epoch"]==first_epoch,"restored exact membership did not recover sparse authority");
  for key in ["routing_selectors","distribution_selectors"] {
   let mut change=mongodb::bson::Document::new();change.insert(key,vec![doc!{"kind":"machine","id":ids[0].to_hex()}]);
   case.app.collection("private_exit_nodes").update_one(doc!{"_id":route},doc!{"$set":change}).await?;
   let (status,_,error)=case.call("POST","/api/access/private/sync","",sender.clone(),&[]).await?;
   ensure!(status==StatusCode::BAD_REQUEST&&error.to_string().contains("upgrade"),"own {key} did not retain complete-plan guard");
   let mut change=mongodb::bson::Document::new();change.insert(key,vec![doc!{"kind":"machine","id":ids[1].to_hex()}]);
   case.app.collection("private_exit_nodes").update_one(doc!{"_id":route},doc!{"$set":change}).await?;
  }
  Ok::<_,anyhow::Error>(())
 }.await;
 case.db.drop().await?;result
}

#[cfg(feature="private-sparse")]
#[tokio::test]
#[ignore="requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn sparse_exit_mode_transition_retires_complete_exit_authority_after_current_group_change()->Result<()> {
 let case=Case::new(Config::default()).await?;
 let result=async {
  let (owner,_)=case.user("sparse-exit-transition@test.invalid","user").await?;
  let ids=[ObjectId::new(),ObjectId::new()];let group=ObjectId::new();
  case.app.collection("machine_groups").insert_one(doc!{"_id":group,"user_id":owner}).await?;
  for (i,id) in ids.iter().enumerate(){
   let mut machine=doc!{"_id":id,"user_id":owner,"name":format!("Transition{i}")};if i==0{machine.insert("group_ids",vec![group]);}
   case.app.collection("machines").insert_one(machine).await?;
   case.app.collection("private_peers").insert_one(doc!{"_id":format!("transition-{i}"),"workspace_id":owner,"machine_id":id,"owner_id":owner,"enabled":true,"ip":format!("10.213.0.{}",i+1),"credential_hash":token_digest("fixture-token-0123456789abcdef0123456789")}).await?;
  }
  case.app.collection("private_networks").insert_one(doc!{"_id":owner.to_hex(),"cidr":"10.213.0.0/24","dns_suffix":"phub"}).await?;
  case.app.collection("private_exit_nodes").insert_one(doc!{"_id":ObjectId::new(),"workspace_id":owner,"name":"Group exit","enabled":true,"routing_selectors":[{"kind":"machine","id":ids[1].to_hex()}],"distribution_selectors":[{"kind":"group","id":group.to_hex()}]}).await?;
  let request=|i:usize|{let mut b=sync(&format!("transition-{i}"),&fingerprint("AB"),"instance-transition-0");b["sparse"]=json!({"protocol":1,"sequence":1,"wanted":[]});b};
  let router=case.status("POST","/api/access/private/sync","",request(1),StatusCode::OK).await?;
  ensure!(router["snapshot"]["sparse"].is_null()&&router["snapshot"]["exit_routes"][0]["clients"]==json!(["transition-0"]),"routing peer lost complete client policy");
  let before=case.status("POST","/api/access/private/sync","",request(0),StatusCode::OK).await?;
  ensure!(before["snapshot"]["sparse"].is_null()&&before["snapshot"]["exit_routes"].as_array().unwrap().len()==1,"client lost complete exit policy");
  let mut engine=porthub_agent::private_network::policy::Engine::default();engine.apply(serde_json::from_value(before["snapshot"].clone())?)?;
  let mut packet=[0u8;28];packet[0]=0x45;packet[2..4].copy_from_slice(&28u16.to_be_bytes());packet[8]=64;packet[9]=17;packet[12..16].copy_from_slice(&[10,213,0,1]);packet[16..20].copy_from_slice(&[8,8,8,8]);packet[20..22].copy_from_slice(&1234u16.to_be_bytes());packet[22..24].copy_from_slice(&53u16.to_be_bytes());packet[24..26].copy_from_slice(&8u16.to_be_bytes());
  let mut sum=packet[..20].chunks_exact(2).map(|p|u32::from(u16::from_be_bytes([p[0],p[1]]))).sum::<u32>();while sum>>16!=0{sum=(sum&65535)+(sum>>16);}packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
  ensure!(porthub_network::policy::Packet::parse(&packet).is_some(),"fixture IPv4 UDP packet is invalid");
  ensure!(engine.check_exit(&packet,"transition-1",false),"actual complete exit policy did not authorize client traffic");
  case.app.collection("machines").update_one(doc!{"_id":ids[0]},doc!{"$unset":{"group_ids":""}}).await?;
  let after=case.status("POST","/api/access/private/sync","",request(0),StatusCode::OK).await?;
  ensure!(after["snapshot"]["sparse"]["protocol"]==1&&after["snapshot"]["exit_routes"]==json!([]),"removed group client kept old exit assignment");
  engine.apply(serde_json::from_value(after["snapshot"].clone())?)?;
  ensure!(!engine.check_exit(&packet,"transition-1",false),"old exit flow survived current group removal");
  Ok::<_,anyhow::Error>(())
 }.await;case.db.drop().await?;result
}

#[cfg(feature="private-sparse")]
#[tokio::test]
#[ignore="requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn participating_exit_4097_uses_exact_bounded_picker_and_reciprocal_authority()->Result<()> {
 let case=Case::new(Config::default()).await?;
 let result=async{
  let(owner,_)=case.user("participating-exit-4097@test.invalid","user").await?;
  let ids:Vec<_>=(0..4097).map(|_|ObjectId::new()).collect();
  case.app.collection("machines").insert_many(ids.iter().enumerate().map(|(i,id)|doc!{"_id":id,"user_id":owner,"name":format!("Picker{i}")})).await?;
  case.app.collection("private_peers").insert_many(ids.iter().enumerate().map(|(i,id)|doc!{"_id":format!("exit-growth-{i}"),"workspace_id":owner,"machine_id":id,"owner_id":owner,"ip":std::net::Ipv4Addr::from(u32::from(std::net::Ipv4Addr::new(10,211,0,1))+i as u32).to_string(),"enabled":true,"credential_hash":token_digest("fixture-token-0123456789abcdef0123456789")})).await?;
  case.app.collection("private_networks").insert_one(doc!{"_id":owner.to_hex(),"cidr":"10.211.0.0/19","dns_suffix":"phub"}).await?;
  let route=ObjectId::new();
  case.app.collection("private_exit_nodes").insert_one(doc!{"_id":route,"workspace_id":owner,"enabled":true,"name":"Bounded full-group exit","selection":"round_robin","routing_selectors":[{"kind":"machine","id":ids[1].to_hex()},{"kind":"machine","id":ids[2].to_hex()}],"distribution_selectors":[{"kind":"machine","id":ids[0].to_hex()}]}).await?;
  let request=|i:usize,wanted:Value|{
   let mut value=sync(&format!("exit-growth-{i}"),&fingerprint("AB"),"instance-exit-grow");
   value["sparse"]=json!({"protocol":1,"sequence":1,"wanted":wanted});value["exit_pair_protocol"]=json!(1);value["exit_ready"]=json!(true);value
  };
  for i in [1,2]{let router=case.status("POST","/api/access/private/sync","",request(i,json!([])),StatusCode::OK).await?;
   ensure!(router["snapshot"]["peers"].as_array().unwrap().len()==1&&router["snapshot"]["exit_routes"]==json!([]),"router materialized complete4097 plan");
   ensure!(router["snapshot"]["sparse"]["exit_intents"][0]["role"]=="router","router intent missing");
  }
  let mut body=request(0,json!([]));
  let initial=case.status("POST","/api/access/private/sync","",body.clone(),StatusCode::OK).await?;
  body["exit_pick"]=json!({"selection_epoch":initial["snapshot"]["sparse"]["selection_epoch"],"route_id":route.to_hex(),"flow_id":"a".repeat(64),"ordinal":0,"destination":"8.8.8.8"});
  let mut reply=case.status("POST","/api/access/private/sync","",body.clone(),StatusCode::OK).await?;
  for _ in 0..8{
   if reply["exit_pick"]["status"]!="pending"{break}
   body["exit_pick"]["cursor"]=reply["exit_pick"]["cursor"].clone();
   reply=case.status("POST","/api/access/private/sync","",body.clone(),StatusCode::OK).await?;
  }
  ensure!(reply["exit_pick"]["status"]=="ready"&&reply["exit_pick"]["choice"]["id"]=="exit-growth-1","full-group round robin first choice failed: {}",reply["exit_pick"]);
  ensure!(reply["snapshot"]["peers"].as_array().unwrap().len()==1&&reply["pair_responses"].as_array().unwrap().len()==1,"unbounded exit participants disclosed");
  let first:porthub_network::policy::PairLease=serde_json::from_value(reply["exit_pick"]["lease"].clone())?;
  ensure!(first.exit.as_ref().is_some_and(|e|e.client=="exit-growth-0"&&e.router=="exit-growth-1"),"incorrect exact exit roles");
  let mut engine=porthub_network::policy::Engine::default();engine.apply(serde_json::from_value(reply["snapshot"].clone())?)?;engine.install_pair(first)?;
  let packet=|to:[u8;4]|{
   let mut packet=[0u8;28];packet[0]=0x45;packet[2..4].copy_from_slice(&28u16.to_be_bytes());packet[8]=64;packet[9]=17;packet[12..16].copy_from_slice(&[10,211,0,1]);packet[16..20].copy_from_slice(&to);packet[20..22].copy_from_slice(&1234u16.to_be_bytes());packet[22..24].copy_from_slice(&53u16.to_be_bytes());packet[24..26].copy_from_slice(&8u16.to_be_bytes());let mut sum=packet[..20].chunks_exact(2).map(|p|u32::from(u16::from_be_bytes([p[0],p[1]]))).sum::<u32>();while sum>>16!=0{sum=(sum&65535)+(sum>>16)}packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());packet
  };
  ensure!(engine.check_exit(&packet([8,8,8,8]),"exit-growth-1",false),"exact API exit lease did not authorize normal Engine exit");
  ensure!(!engine.check(&packet([10,211,0,2]),"exit-growth-1",false),"exit-only lease granted ordinary private port access");
  let reciprocal=case.status("POST","/api/access/private/sync","",request(1,json!([{"kind":"peer","value":"exit-growth-0"}])),StatusCode::OK).await?;
  ensure!(reciprocal["pair_responses"][0]["status"]=="allowed"&&reciprocal["pair_responses"][0]["lease"]["exit"]["client"]=="exit-growth-0","router reciprocal exit lookup required unrelated private ACL");
  // The configured next ordinal sees every eligible router, independent of
  // which leases or transports the client happened to cache.
  body["exit_pick"].as_object_mut().unwrap().remove("cursor");body["exit_pick"]["ordinal"]=json!(1);body["exit_pick"]["flow_id"]=json!("b".repeat(64));
  let mut second=case.status("POST","/api/access/private/sync","",body.clone(),StatusCode::OK).await?;
  for _ in 0..8{if second["exit_pick"]["status"]!="pending"{break}body["exit_pick"]["cursor"]=second["exit_pick"]["cursor"].clone();second=case.status("POST","/api/access/private/sync","",body.clone(),StatusCode::OK).await?;}
  ensure!(second["exit_pick"]["choice"]["id"]=="exit-growth-2","round robin selected only cached router");
  let tcp=|flags:u8,reverse:bool|{
   let mut packet=[0u8;40];packet[0]=0x45;packet[2..4].copy_from_slice(&40u16.to_be_bytes());packet[8]=64;packet[9]=6;
   packet[12..16].copy_from_slice(if reverse{&[8,8,8,8]}else{&[10,211,0,1]});packet[16..20].copy_from_slice(if reverse{&[10,211,0,1]}else{&[8,8,8,8]});
   packet[20..22].copy_from_slice(&(if reverse{443u16}else{1234u16}).to_be_bytes());packet[22..24].copy_from_slice(&(if reverse{1234u16}else{443u16}).to_be_bytes());packet[32]=0x50;packet[33]=flags;
   let mut sum=packet[..20].chunks_exact(2).map(|p|u32::from(u16::from_be_bytes([p[0],p[1]]))).sum::<u32>();while sum>>16!=0{sum=(sum&65535)+(sum>>16)}packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());packet
  };
  ensure!(engine.check_exit(&tcp(2,false),"exit-growth-1",false)&&engine.check_exit(&tcp(18,true),"exit-growth-1",true)&&engine.check_exit(&tcp(16,false),"exit-growth-1",false),"TCP fixture did not establish normal exit flow");
  let permission=second["snapshot"]["sparse"]["exit_epoch"].clone();let mut choice=second["snapshot"]["sparse"]["selection_epoch"].clone();
  for change in [doc!{"selection":"sticky"},doc!{"tor_circuit_groups":8_i64},doc!{"allow_direct_fallback":true},doc!{"routing_selectors":[{"kind":"machine","id":ids[2].to_hex()},{"kind":"machine","id":ids[1].to_hex()}]}]{
   case.app.collection("private_exit_nodes").update_one(doc!{"_id":route},doc!{"$set":change}).await?;
   let refreshed=case.status("POST","/api/access/private/sync","",request(0,json!([])),StatusCode::OK).await?;
   ensure!(refreshed["snapshot"]["sparse"]["exit_epoch"]==permission&&refreshed["snapshot"]["sparse"]["selection_epoch"]!=choice,"scheduling failed to separate permission from cold choices");choice=refreshed["snapshot"]["sparse"]["selection_epoch"].clone();
   engine.apply(serde_json::from_value(refreshed["snapshot"].clone())?)?;
   ensure!(engine.check_exit(&tcp(16,false),"exit-growth-1",false)&&engine.check_exit(&packet([8,8,8,8]),"exit-growth-1",false),"unchanged established TCP/UDP retired on scheduling-only edit");
  }
  body["exit_pick"].as_object_mut().unwrap().remove("cursor");
  let stale=case.status("POST","/api/access/private/sync","",body.clone(),StatusCode::OK).await?;
  ensure!(stale["exit_pick"]["status"]=="unavailable"&&stale["exit_pick"]["lease"].is_null()&&stale["snapshot"]["sparse"]["selection_epoch"]==choice,"stale cold choice blocked convergence or granted authority");

  case.app.collection("private_exit_nodes").update_one(doc!{"_id":route},doc!{"$set":{"enabled":false}}).await?;
  let revoked=case.status("POST","/api/access/private/sync","",request(0,json!([])),StatusCode::OK).await?;
  engine.apply(serde_json::from_value(revoked["snapshot"].clone())?)?;
  ensure!(!engine.check_exit(&packet([8,8,8,8]),"exit-growth-1",false),"current membership/route removal retained exit authority");
  ensure!(!engine.check_exit(&tcp(16,false),"exit-growth-1",false),"permission withdrawal retained established TCP");
  let denied_router=case.status("POST","/api/access/private/sync","",request(1,json!([{"kind":"peer","value":"exit-growth-0"}])),StatusCode::OK).await?;
  ensure!(denied_router["pair_responses"][0]["status"]!="allowed","withdrawn route retained reciprocal exit authority");

  Ok::<_,anyhow::Error>(())
 }.await;case.db.drop().await?;result
}
