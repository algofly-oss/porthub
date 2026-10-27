use anyhow::{ensure, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId};
use porthub_api::config::Config;
use serde_json::{json, Value};
mod support;
use support::Case;

fn route(name: &str, routing: &[ObjectId], clients: &[ObjectId], mode: &str) -> Value {
    let selectors = |ids: &[ObjectId]| ids.iter().map(|id| json!({"kind":"machine", "id":id.to_hex()})).collect::<Vec<_>>();
    json!({"name":name,"routing_selectors":selectors(routing),"distribution_selectors":selectors(clients),"selection":mode})
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn exit_selection_is_owned_and_rejects_ambiguous_or_recursive_routes() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result = async {
        let (owner, cookie) = case.user("exit-owner@example.invalid", "user").await?;
        let (other, other_cookie) = case.user("exit-other@example.invalid", "user").await?;
        let (luna, condor, miro, foreign) = (ObjectId::new(), ObjectId::new(), ObjectId::new(), ObjectId::new());
        for (id, user, name) in [(luna, owner, "luna"), (condor, owner, "condor"), (miro, owner, "miro"), (foreign, other, "foreign")] {
            case.app.collection("machines").insert_one(doc! {"_id":id,"user_id":user,"name":name}).await?;
            case.app.collection("private_peers").insert_one(doc! {"_id":name,"workspace_id":user,"machine_id":id,"enabled":true,"credential_hash":"test-enrolled"}).await?;
        }
        let endpoint = "/api/access/exit-nodes";
        case.status("POST", endpoint, &cookie, route("self", &[luna], &[luna], "sticky"), StatusCode::BAD_REQUEST).await?;
        case.status("POST", endpoint, &cookie, route("foreign", &[foreign], &[miro], "sticky"), StatusCode::BAD_REQUEST).await?;
        case.status("POST", endpoint, &cookie, route("unknown-mode", &[luna], &[miro], "per_packet"), StatusCode::UNPROCESSABLE_ENTITY).await?;
        let created = case.status("POST", endpoint, &cookie, route("balanced", &[luna, condor], &[miro], "round_robin"), StatusCode::OK).await?;
        ensure!(created["data"]["selection"] == "round_robin");
        ensure!(created["data"]["allow_direct_fallback"] == false);
        let id = created["data"]["_id"].as_str().unwrap();
        let item = format!("{endpoint}/{id}");
        case.status("POST", endpoint, &cookie, route("duplicate", &[luna], &[miro], "random"), StatusCode::CONFLICT).await?;
        case.status("POST", endpoint, &cookie, route("cycle", &[miro], &[luna], "sticky"), StatusCode::CONFLICT).await?;
        case.status("PUT", &item, &other_cookie, route("steal", &[foreign], &[foreign], "sticky"), StatusCode::NOT_FOUND).await?;
        for mode in ["sticky", "random", "round_robin"] {
            let updated = case.status("PUT", &item, &cookie, route("balanced", &[luna, condor], &[miro], mode), StatusCode::OK).await?;
            ensure!(updated["data"]["selection"] == mode);
        }
        let mut direct = route("balanced", &[luna, condor], &[miro], "sticky");
        direct["allow_direct_fallback"] = json!(true);
        let updated = case.status("PUT", &item, &cookie, direct.clone(), StatusCode::OK).await?;
        ensure!(updated["data"]["allow_direct_fallback"] == true);
        let stored = case.app.collection("private_exit_nodes").find_one(doc! {"_id":ObjectId::parse_str(id)?}).await?.unwrap();
        ensure!(stored.get_bool("allow_direct_fallback") == Ok(true));
        direct["allow_direct_fallback"] = json!("yes");
        case.status("PUT", &item, &cookie, direct, StatusCode::UNPROCESSABLE_ENTITY).await?;
        case.status("DELETE", &item, &other_cookie, Value::Null, StatusCode::NOT_FOUND).await?;
        case.status("DELETE", &item, &cookie, Value::Null, StatusCode::OK).await?;
        ensure!(case.app.collection("private_exit_nodes").count_documents(doc! {}).await? == 0);
        Ok::<_, anyhow::Error>(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn group_edits_cannot_create_exit_loops_or_remove_the_last_peer() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result = async {
        let (owner, cookie) = case.user("exit-groups@example.invalid", "user").await?;
        let (exit, consumer, group) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        case.app.collection("machine_groups").insert_one(doc! {"_id":group,"user_id":owner,"name":"exits"}).await?;
        for (machine, groups) in [(exit, vec![group]), (consumer, vec![])] {
            case.app.collection("machines").insert_one(doc! {"_id":machine,"user_id":owner,"name":machine.to_hex(),"group_ids":groups}).await?;
            case.app.collection("private_peers").insert_one(doc! {"_id":machine.to_hex(),"workspace_id":owner,"machine_id":machine,"enabled":true,"credential_hash":"test"}).await?;
        }
        case.status("POST", "/api/access/exit-nodes", &cookie, json!({"name":"group exits","routing_selectors":[{"kind":"group","id":group.to_hex()}],"distribution_selectors":[{"kind":"machine","id":consumer.to_hex()}]}), StatusCode::OK).await?;
        // Both the machine editor and access-rules group editor must validate
        // the proposed complete graph before touching machine memberships.
        case.status("POST", "/api/machines/groups/add", &cookie, json!({"machine_id":consumer.to_hex(),"group_id":group.to_hex()}), StatusCode::CONFLICT).await?;
        case.status("POST", "/api/machines/groups/remove", &cookie, json!({"machine_id":exit.to_hex(),"group_id":group.to_hex()}), StatusCode::CONFLICT).await?;
        case.status("PUT", &format!("/api/access/groups/{group}/members"), &cookie, json!({"machine_ids":[exit.to_hex(),consumer.to_hex()],"user_ids":[]}), StatusCode::CONFLICT).await?;
        let record = case.app.collection("machines").find_one(doc! {"_id":consumer}).await?.unwrap();
        ensure!(porthub_api::domain::inventory::group_ids(&record).is_empty());
        let record = case.app.collection("machines").find_one(doc! {"_id":exit}).await?.unwrap();
        ensure!(porthub_api::domain::inventory::group_ids(&record) == vec![group]);
        case.status("PUT", &format!("/api/access/groups/{group}/members"), &cookie, json!({"machine_ids":[exit.to_hex()],"user_ids":[]}), StatusCode::OK).await?;
        Ok::<_, anyhow::Error>(())
    }.await;
    case.db.drop().await?;
    result
}
