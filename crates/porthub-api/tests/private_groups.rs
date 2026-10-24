use anyhow::{ensure, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId, Bson};
use porthub_api::config::Config;
use serde_json::json;
#[allow(dead_code)]
mod support;
use support::Case;

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn workspace_group_mutation_checks_all_selectors_before_preserving_legacy_membership(
) -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result = async {
        let (owner, cookie) = case.user("group-owner@test.invalid", "user").await?;
        let (member, member_cookie) = case.user("group-member@test.invalid", "user").await?;
        let (foreign, _) = case.user("group-foreign@test.invalid", "user").await?;
        case.app.collection("workspace_members").insert_one(doc!{"_id":format!("{owner}:{member}"),"workspace_id":owner,"user_id":member,"role":"member"}).await?;
        let base = "/api/access/groups";
        let created = case.status("POST",base,&cookie,json!({"name":"  Production  "}),StatusCode::OK).await?;
        ensure!(created["data"]["name"] == "Production" && created["data"]["user_ids"] == json!([]));
        let group = ObjectId::parse_str(created["data"]["_id"].as_str().unwrap())?;
        case.status("POST",base,&cookie,json!({"name":"Production"}),StatusCode::CONFLICT).await?;
        case.status("POST",base,&cookie,json!({"name":"界".repeat(81)}),StatusCode::BAD_REQUEST).await?;
        case.status("POST",base,&cookie,json!([]),StatusCode::UNPROCESSABLE_ENTITY).await?;
        let scoped = format!("{base}?workspace={owner}");
        case.status("POST",&scoped,&member_cookie,json!({"name":"Blocked"}),StatusCode::FORBIDDEN).await?;
        let (status, _, _) = case.call("POST",base,&cookie,json!({"name":"Blocked"}),&[("origin","https://other.invalid")]).await?;
        ensure!(status == StatusCode::FORBIDDEN);
        let original = ObjectId::new();
        let machines = [ObjectId::new(),ObjectId::new(),ObjectId::new()];
        case.app.collection("machines").insert_many([
            doc!{"_id":machines[0],"user_id":owner,"group_id":original,"name":"Legacy","token":"group-private-token-must-not-leak"},
            doc!{"_id":machines[1],"user_id":owner,"group_ids":[Bson::String(group.to_hex()),Bson::ObjectId(original)],"name":"Modern"},
            doc!{"_id":machines[2],"user_id":foreign,"group_ids":[group],"name":"Foreign"},
        ]).await?;
        let path = format!("{base}/{group}/members");
        case.status("PUT",&path,&cookie,json!({"machine_ids":[machines[2].to_hex()]}),StatusCode::BAD_REQUEST).await?;
        case.status("PUT",&path,&cookie,json!({"machine_ids":[machines[0].to_hex()],"user_ids":[foreign.to_hex()]}),StatusCode::BAD_REQUEST).await?;
        let unchanged = case.app.collection("machines").find_one(doc!{"_id":machines[0]}).await?.unwrap();
        ensure!(unchanged.get_object_id("group_id")? == original && !unchanged.contains_key("group_ids"));
        let invalid = case.status("PUT",&path,&cookie,json!({"machine_ids":null}),StatusCode::UNPROCESSABLE_ENTITY).await?;
        ensure!(invalid["detail"][0]["loc"] == json!(["body","machine_ids"]));
        case.status("PUT",&path,&cookie,json!({"machine_ids":vec![machines[0].to_hex();1001]}),StatusCode::UNPROCESSABLE_ENTITY).await?;
        case.status("PUT",&path,&cookie,json!({"user_ids":["bad-id"]}),StatusCode::BAD_REQUEST).await?;
        case.status("PUT",&format!("{path}?workspace={owner}"),&member_cookie,json!({}),StatusCode::FORBIDDEN).await?;
        let response = case.status("PUT",&path,&cookie,json!({"machine_ids":[machines[0].to_hex(),machines[0].to_hex()],"user_ids":[member.to_hex(),owner.to_hex(),member.to_hex()]}),StatusCode::OK).await?;
        ensure!(response == json!({"msg":"Group members saved"}));
        let legacy = case.app.collection("machines").find_one(doc!{"_id":machines[0]}).await?.unwrap();
        ensure!(!legacy.contains_key("group_id") && legacy.get_array("group_ids")? == &vec![Bson::ObjectId(original),Bson::ObjectId(group)]);
        let modern = case.app.collection("machines").find_one(doc!{"_id":machines[1]}).await?.unwrap();
        ensure!(modern.get_array("group_ids")? == &vec![Bson::ObjectId(original)]);
        let record = case.app.collection("machine_groups").find_one(doc!{"_id":group}).await?.unwrap();
        ensure!(record.get_array("user_ids")? == &vec![Bson::ObjectId(member),Bson::ObjectId(owner)]);
        let snapshot = case.status("GET","/api/access/snapshot",&cookie,json!(null),StatusCode::OK).await?;
        ensure!(!snapshot.to_string().contains("must-not-leak"));
        // Administrators can save membership; default empty arrays remove only
        // this group's label and preserve all other groups and foreign owners.
        case.app.collection("workspace_members").update_one(doc!{"workspace_id":owner,"user_id":member},doc!{"$set":{"role":"admin"}}).await?;
        case.status("PUT",&format!("{path}?workspace={owner}"),&member_cookie,json!({}),StatusCode::OK).await?;
        let cleared = case.app.collection("machines").find_one(doc!{"_id":machines[0]}).await?.unwrap();
        ensure!(cleared.get_array("group_ids")? == &vec![Bson::ObjectId(original)]);
        let untouched = case.app.collection("machines").find_one(doc!{"_id":machines[2]}).await?.unwrap();
        ensure!(untouched.get_array("group_ids")? == &vec![Bson::ObjectId(group)]);
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}
