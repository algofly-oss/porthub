use anyhow::{ensure, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use porthub_api::{config::Config, domain::private_names};
use serde_json::json;
mod support;
use support::Case;

#[test]
fn private_names_preserve_enrollment_order_custom_names_aliases_and_typed_ids() {
    let mid = ObjectId::parse_str("00000000000000000000abcd").unwrap();
    let other = ObjectId::parse_str("11111111111111111111abcd").unwrap();
    let last = ObjectId::parse_str("22222222222222222222abcd").unwrap();
    let machines = vec![
        doc! {"_id":mid,"name":"Luna","aliases":["shared","Miro","own","own"]},
        doc! {"_id":mid.to_hex(),"name":"Incorrect typed identity"},
        doc! {"_id":other,"name":"Luna","aliases":["shared","other"]},
        doc! {"_id":last,"name":"Luna"},
        doc! {"_id":ObjectId::new(),"name":"Miro"},
    ];
    let mut peers = vec![
        doc! {"_id":"last","machine_id":last,"created_at":"2026-03"},
        doc! {"_id":"second","machine_id":other,"created_at":"2026-02"},
        doc! {"_id":"first","machine_id":mid,"created_at":"2026-01"},
        doc! {"_id":"custom","machine_id":ObjectId::new(),"hostname":"luna"},
    ];
    let names = private_names::assign(&machines, &peers);
    assert_eq!(names.primary["custom"], "luna");
    assert_eq!(names.primary["first"], "luna-abcd");
    assert_eq!(names.primary["second"], "luna-abcd-2");
    assert_eq!(names.primary["last"], "luna-abcd-3");
    assert_eq!(names.aliases["first"], ["shared", "own"]);
    assert_eq!(names.aliases["second"], ["other"]);
    peers.reverse();
    let reversed = private_names::assign(&machines, &peers);
    assert_eq!(names.primary, reversed.primary);
    assert_eq!(names.aliases, reversed.aliases);
    assert_eq!(
        private_names::label(Some(&"  Foo___BAR..9  ".into())),
        "foo-bar-9"
    );
    assert_eq!(private_names::label(Some(&"☀☀".into())), "machine");
    assert!(private_names::label(Some(&"A".repeat(90).into())).len() <= 48);
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn private_snapshot_is_workspace_scoped_redacted_and_role_aware() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result = async {
        let (owner,cookie)=case.user("private-owner@test.invalid","user").await?;
        let (member,member_cookie)=case.user("private-member@test.invalid","user").await?;
        let (foreign,foreign_cookie)=case.user("private-foreign@test.invalid","user").await?;
        let machine=ObjectId::new();
        let invited=ObjectId::new();
        let group=ObjectId::new();
        case.app.collection("workspace_members").insert_one(doc!{"_id":format!("{owner}:{member}"),"workspace_id":owner,"user_id":member,"role":"member"}).await?;
        case.app.collection("machines").insert_many([
            doc!{"_id":machine,"user_id":owner,"name":"Luna","token":"secret-machine-token","group_ids":[group]},
            doc!{"_id":invited,"user_id":member,"name":"Miro","aliases":["secondary"],"token":"secret-invited-token"},
            doc!{"_id":ObjectId::new(),"user_id":foreign,"name":"unrelated-machine"},
            doc!{"_id":ObjectId::new(),"user_id":owner,"name":"deleted-machine","deletion_pending":true},
        ]).await?;
        case.app.collection("private_peers").insert_many([
            doc!{"_id":"owner-peer","workspace_id":owner,"machine_id":machine,"ip":"10.203.0.10","credential_hash":"secret-private-hash","fingerprint":"secret-fingerprint","last_seen_at":DateTime::now(),"paths":{"a":"direct","b":"direct","c":"relay"}},
            doc!{"_id":"invited-peer","workspace_id":owner,"machine_id":invited,"ip":"10.203.0.11","enabled":false},
            doc!{"_id":"unrelated-peer","workspace_id":foreign,"machine_id":ObjectId::new(),"ip":"10.203.0.12"},
        ]).await?;
        case.app.collection("machine_groups").insert_one(doc!{"_id":group,"user_id":owner,"name":"Devices","user_ids":[owner,member,foreign]}).await?;
        case.app.collection("access_rulebooks").insert_one(doc!{"_id":ObjectId::new(),"user_id":owner,"name":"Private rules","group_id":group.to_hex(),"rules":[],"unexpected_secret":"secret-book-field"}).await?;
        case.app.collection("workspace_invites").insert_one(doc!{"_id":"invite-hash","user_id":owner,"email":"pending@test.invalid","role":"member","expires_at":DateTime::from_millis(DateTime::now().timestamp_millis()+60000),"extra_secret":"must-not-return"}).await?;
        let body=case.status("GET","/api/access/snapshot",&cookie,json!(null),StatusCode::OK).await?;
        ensure!(body["machines"].as_array().unwrap().len()==1);
        ensure!(body["private_peers"].as_array().unwrap().len()==2);
        let peers=body["private_peers"].as_array().unwrap();
        let luna=peers.iter().find(|p|p["_id"]=="owner-peer").unwrap();
        ensure!(luna["hostname"]=="luna" && luna["installed"]==true && luna["online"]==true);
        ensure!(luna["paths"]==json!(["direct","relay"]));
        let miro=peers.iter().find(|p|p["_id"]=="invited-peer").unwrap();
        ensure!(miro["hostname"]=="miro" && miro["machine_name"]=="Miro" && miro["aliases"]==json!(["secondary"]));
        ensure!(body["groups"][0]["user_ids"]==json!([owner.to_hex(),member.to_hex()]));
        ensure!(body["invitations"].as_array().unwrap().len()==1);
        let text=body.to_string();
        for excluded in ["secret-machine-token","secret-invited-token","secret-private-hash","secret-fingerprint","secret-book-field","unrelated-machine","unrelated-peer","deleted-machine","must-not-return"] { ensure!(!text.contains(excluded),"inventory leaks {excluded}"); }
        let path=format!("/api/access/snapshot?workspace={owner}");
        let member_body=case.status("GET",&path,&member_cookie,json!(null),StatusCode::OK).await?;
        ensure!(member_body["role"]=="member" && member_body["invitations"]==json!([]));
        case.status("GET",&path,&foreign_cookie,json!(null),StatusCode::FORBIDDEN).await?;
        case.app.collection("workspace_members").delete_one(doc!{"_id":format!("{owner}:{member}")}).await?;
        case.status("GET",&path,&member_cookie,json!(null),StatusCode::FORBIDDEN).await?;
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn network_changes_validate_permissions_and_preserve_existing_peer_addresses() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result=async {
        let (owner,cookie)=case.user("network-owner@test.invalid","user").await?;
        let (member,member_cookie)=case.user("network-member@test.invalid","user").await?;
        case.app.collection("workspace_members").insert_one(doc!{"_id":format!("{owner}:{member}"),"workspace_id":owner,"user_id":member,"role":"member"}).await?;
        case.app.collection("private_peers").insert_one(doc!{"_id":"existing","workspace_id":owner,"ip":"10.203.0.10","credential_hash":"unchanged"}).await?;
        let body=json!({"cidr":"192.168.40.0/24","dns_suffix":"LAN.Example.COM.","ignored":u64::MAX});
        let path=format!("/api/access/network?workspace={owner}");
        case.status("PUT",&path,&member_cookie,body.clone(),StatusCode::FORBIDDEN).await?;
        let (status,_,_)=case.call("PUT",&path,&cookie,body.clone(),&[("origin","https://evil.test")]).await?;
        ensure!(status==StatusCode::FORBIDDEN);
        case.status("PUT",&path,&cookie,json!({"cidr":"8.8.8.0/24"}),StatusCode::UNPROCESSABLE_ENTITY).await?;
        let saved=case.status("PUT",&path,&cookie,body,StatusCode::OK).await?;
        ensure!(saved["data"]["dns_suffix"]=="lan.example.com");
        ensure!(saved["transport_ready"]==false);
        let peer=case.app.collection("private_peers").find_one(doc!{"_id":"existing"}).await?.unwrap();
        ensure!(peer.get_str("ip")==Ok("10.203.0.10") && peer.get_str("credential_hash")==Ok("unchanged"));
        ensure!(case.app.collection("private_networks").count_documents(doc!{}).await?==1);
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn private_peer_disable_and_revocation_are_scoped_and_preserve_public_access() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result=async {
        let (owner,cookie)=case.user("peer-owner@test.invalid","user").await?;
        let (member,member_cookie)=case.user("peer-member@test.invalid","user").await?;
        let (foreign,foreign_cookie)=case.user("peer-foreign@test.invalid","user").await?;
        case.app.collection("workspace_members").insert_one(doc!{"_id":format!("{owner}:{member}"),"workspace_id":owner,"user_id":member,"role":"member"}).await?;
        let machine=ObjectId::new();
        let public=doc!{"_id":machine,"user_id":owner,"token":"public-token","enabled":true};
        case.app.collection("machines").insert_one(public.clone()).await?;
        case.app.collection("private_peers").insert_many([
            doc!{"_id":"owned-peer","workspace_id":owner,"owner_id":owner,"machine_id":machine,"enabled":true,"ip":"10.203.0.10","credential_hash":"secret","fingerprint":"fingerprint","instance":"instance"},
            doc!{"_id":"member-peer","workspace_id":owner,"owner_id":member,"enabled":true,"credential_hash":"member-secret"},
            doc!{"_id":"foreign-peer","workspace_id":foreign,"owner_id":foreign,"enabled":true,"credential_hash":"foreign-secret"},
        ]).await?;
        case.app.collection("private_install_tickets").insert_one(doc!{"_id":"ticket","peer_id":"owned-peer"}).await?;
        case.app.collection("private_signals").insert_many([
            doc!{"_id":"outgoing","from":"owned-peer","to":"member-peer"},
            doc!{"_id":"incoming","from":"member-peer","to":"owned-peer"},
            doc!{"_id":"unrelated","from":"foreign-peer","to":"elsewhere"},
        ]).await?;
        let path=format!("/api/access/private/peers/owned-peer?workspace={owner}");
        case.status("PUT",&path,&member_cookie,json!({"enabled":false}),StatusCode::FORBIDDEN).await?;
        case.status("DELETE",&path,&member_cookie,json!(null),StatusCode::NOT_FOUND).await?;
        case.status("DELETE",&path,&foreign_cookie,json!(null),StatusCode::FORBIDDEN).await?;
        case.status("PUT",&path,&cookie,json!({}),StatusCode::UNPROCESSABLE_ENTITY).await?;
        case.status("PUT",&path,&cookie,json!({"enabled":false}),StatusCode::OK).await?;
        let disabled=case.app.collection("private_peers").find_one(doc!{"_id":"owned-peer"}).await?.unwrap();
        ensure!(disabled.get_bool("enabled")==Ok(false) && disabled.get_str("credential_hash")==Ok("secret"));
        case.status("PUT",&path,&cookie,json!({"enabled":"yes"}),StatusCode::OK).await?;
        let (status,_,_)=case.call("DELETE",&path,&cookie,json!(null),&[("origin","https://evil.test")]).await?;
        ensure!(status==StatusCode::FORBIDDEN);
        case.status("DELETE",&path,&cookie,json!(null),StatusCode::OK).await?;
        let revoked=case.app.collection("private_peers").find_one(doc!{"_id":"owned-peer"}).await?.unwrap();
        ensure!(revoked.get_bool("enabled")==Ok(false) && revoked.get_str("ip")==Ok("10.203.0.10"));
        for field in ["credential_hash","fingerprint","instance"] { ensure!(!revoked.contains_key(field)); }
        let ticket=case.app.collection("private_install_tickets").find_one(doc!{"_id":"ticket"}).await?.unwrap();
        ensure!(ticket.get_datetime("consumed_at").is_ok());
        ensure!(case.app.collection("private_signals").count_documents(doc!{}).await?==1);
        ensure!(case.app.collection("machines").find_one(doc!{"_id":machine}).await?.unwrap()==public);
        let foreign_peer=case.app.collection("private_peers").find_one(doc!{"_id":"foreign-peer"}).await?.unwrap();
        ensure!(foreign_peer.get_str("credential_hash")==Ok("foreign-secret"));
        let own_path=format!("/api/access/private/peers/member-peer?workspace={owner}");
        case.status("DELETE",&own_path,&member_cookie,json!(null),StatusCode::OK).await?;
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}
