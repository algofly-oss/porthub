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
        let request0=sync("peer-0",&fp0,"instance-00000000");
        let request1=sync("peer-1",&fp1,"instance-11111111");
        let mut bad=request0.clone();bad["token"]=json!("wrong-token-0123456789abcdef0123456789");
        case.status("POST","/api/access/private/sync","",bad,StatusCode::FORBIDDEN).await?;
        case.status("POST","/api/access/private/sync","",request1.clone(),StatusCode::OK).await?;
        let (status,headers,initial)=case.call("POST","/api/access/private/sync","",request0.clone(),&[]).await?;
        ensure!(status==StatusCode::OK && headers["cache-control"]=="no-store");
        ensure!(initial["snapshot"]["self"]=="peer-0" && initial["snapshot"]["workspace"]==owner.to_hex());
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
