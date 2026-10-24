use anyhow::{ensure, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime};
use porthub_api::{
    config::Config,
    domain::{private_enrollment as enrollment, workspaces::token_digest},
};
use serde_json::{json, Value};
mod support;
use support::Case;
#[test]
fn enrollment_hostname_and_bootstrap_models_match_original_fixtures() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/private-enrollment.json")).unwrap();
    for case in cases {
        let raw = serde_json::from_str(case["body"].as_str().unwrap()).unwrap();
        let actual = match case["model"].as_str().unwrap() {
            "PeerEnrollment" => enrollment::parse(raw).map(|(id, name)| {
                // The returned effective name combines hostname/alias; fixture
                // checks the two separately through their own validation too.
                let body: Value = serde_json::from_str(case["body"].as_str().unwrap()).unwrap();
                let hostname = enrollment::parse_hostname(json!({"hostname":body.get("hostname")}))
                    .ok()
                    .flatten();
                let alias = enrollment::parse_hostname(json!({"hostname":body.get("alias")}))
                    .ok()
                    .flatten();
                let _ = name;
                json!({"machine_id":id,"hostname":hostname,"alias":alias})
            }),
            "HostnameChange" => {
                enrollment::parse_hostname(raw).map(|hostname| json!({"hostname":hostname}))
            }
            "Bootstrap" => enrollment::parse_ticket(raw).map(|ticket| json!({"ticket":ticket})),
            _ => unreachable!(),
        }
        .unwrap_or_else(|e| json!({"detail":e.detail}));
        assert_eq!(actual, case["response"], "{}", case["body"]);
    }
}
fn short_path(response: &Value) -> String {
    url::Url::parse(
        response["native_command"]
            .as_str()
            .unwrap()
            .split_whitespace()
            .last()
            .unwrap(),
    )
    .unwrap()
    .path()
    .into()
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn native_private_enrollment_preserves_address_claims_once_and_syncs_issued_identity(
) -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result=async {
        let (owner,cookie)=case.user("private-enrollment-owner@test.invalid","user").await?;
        let machine=case.status("POST","/api/machines/add",&cookie,json!({"name":"Luna"}),StatusCode::OK).await?["data"].clone();
        let id=machine["_id"].as_str().unwrap();let peer=format!("{owner}:{id}");
        let before=case.app.collection("private_peers").find_one(doc!{"_id":&peer}).await?.unwrap();
        let enrolled=case.status("POST","/api/access/private/peers",&cookie,json!({"machine_id":id,"hostname":"Studio"}),StatusCode::OK).await?;
        ensure!(enrolled["peer_id"]==peer && enrolled["ip"]==before.get_str("ip")? && enrolled["hostname"]=="studio.phub");
        let link=short_path(&enrolled);
        let (status,headers,metadata)=case.call("GET",&link,"",json!(null),&[("accept","application/json")]).await?;
        ensure!(status==StatusCode::OK && headers["cache-control"]=="no-store" && metadata["kind"]=="private");
        ensure!(metadata["ticket"]==enrolled["ticket"] && metadata["peer_id"]==peer && metadata.get("profile").is_none());
        let ticket=json!({"ticket":enrolled["ticket"]});
        let (a,b)=tokio::join!(case.call("POST","/api/access/private/bootstrap","",ticket.clone(),&[]),case.call("POST","/api/access/private/bootstrap","",ticket,&[]));
        let a=a?;let b=b?;ensure!((a.0==StatusCode::OK && b.0==StatusCode::FORBIDDEN)||(b.0==StatusCode::OK && a.0==StatusCode::FORBIDDEN));
        let credentials=if a.0==StatusCode::OK {a.2} else {b.2};
        ensure!(credentials["peer_id"]==peer && credentials["workspace"]==owner.to_hex());
        let after=case.app.collection("private_peers").find_one(doc!{"_id":&peer}).await?.unwrap();
        ensure!(after.get_str("ip")?==before.get_str("ip")? && after.get_str("credential_hash")?==token_digest(credentials["token"].as_str().unwrap()));
        case.status("GET",&link,"",json!(null),StatusCode::FORBIDDEN).await?;
        let response=case.status("POST","/api/access/private/sync","",json!({"peer_id":peer,"token":credentials["token"],"fingerprint":vec!["AB";32].join(":"),"instance":"native-instance-0123456789"}),StatusCode::OK).await?;
        ensure!(response["snapshot"]["peers"].as_array().unwrap().len()==1);
        case.status("POST","/api/access/private/peers",&cookie,json!({"machine_id":id}),StatusCode::CONFLICT).await?;
        let path=format!("/api/access/private/peers/{peer}/hostname");
        ensure!(case.status("PUT",&path,&cookie,json!({"hostname":"new-studio"}),StatusCode::OK).await?["hostname"]=="new-studio");
        ensure!(case.status("PUT",&path,&cookie,json!({}),StatusCode::OK).await?["hostname"]=="luna");
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn reissued_tickets_and_revoked_issuers_cannot_redeem_old_private_capabilities() -> Result<()>
{
    let case = Case::new(Config::default()).await?;
    let result=async {
        let (owner,cookie)=case.user("private-reissue-owner@test.invalid","user").await?;
        let (member,member_cookie)=case.user("private-reissue-member@test.invalid","user").await?;
        let (foreign,foreign_cookie)=case.user("private-reissue-foreign@test.invalid","user").await?;
        let machine=ObjectId::new();
        case.app.collection("machines").insert_one(doc!{"_id":machine,"user_id":member,"name":"Miro","token":"public-token"}).await?;
        case.app.collection("workspace_members").insert_one(doc!{"_id":format!("{owner}:{member}"),"workspace_id":owner,"user_id":member,"role":"member"}).await?;
        let path=format!("/api/access/private/peers?workspace={owner}");let body=json!({"machine_id":machine.to_hex()});
        case.status("POST",&path,&foreign_cookie,body.clone(),StatusCode::FORBIDDEN).await?;
        let first=case.status("POST",&path,&member_cookie,body.clone(),StatusCode::OK).await?;
        let second=case.status("POST",&path,&member_cookie,body,StatusCode::OK).await?;
        ensure!(first["ip"]==second["ip"] && first["peer_id"]==second["peer_id"] && first["ticket"]!=second["ticket"]);
        case.status("POST","/api/access/private/bootstrap","",json!({"ticket":first["ticket"]}),StatusCode::FORBIDDEN).await?;
        case.status("GET",&short_path(&first),"",json!(null),StatusCode::FORBIDDEN).await?;
        case.app.collection("workspace_members").delete_one(doc!{"_id":format!("{owner}:{member}")}).await?;
        case.status("POST","/api/access/private/bootstrap","",json!({"ticket":second["ticket"]}),StatusCode::FORBIDDEN).await?;
        // A pending legacy Go ticket remains readable without an epoch field.
        let legacy=ObjectId::new();let peer=format!("{owner}:{legacy}");let ticket="legacy-private-ticket-0123456789abcdef";
        case.app.collection("machines").insert_one(doc!{"_id":legacy,"user_id":owner,"name":"Legacy","token":"legacy-public-token"}).await?;
        case.app.collection("private_peers").insert_one(doc!{"_id":&peer,"workspace_id":owner,"machine_id":legacy,"owner_id":owner,"enabled":true,"ip":"10.203.0.222"}).await?;
        case.app.collection("private_install_tickets").insert_one(doc!{"_id":token_digest(ticket),"peer_id":&peer,"created_by":owner,"consumed_at":Bson::Null,"expires_at":DateTime::from_millis(DateTime::now().timestamp_millis()+60000)}).await?;
        let redeemed=case.status("POST","/api/access/private/bootstrap","",json!({"ticket":ticket}),StatusCode::OK).await?;
        ensure!(redeemed["peer_id"]==peer);
        let _=(cookie,foreign);Ok(())
    }.await;
    case.db.drop().await?;
    result
}
