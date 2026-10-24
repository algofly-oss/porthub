use anyhow::{ensure, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId};
use porthub_api::config::Config;
use serde_json::{json, Value};
mod support;
use support::Case;
fn book(group: ObjectId, source: ObjectId, destination: ObjectId) -> Value {
    json!({"name":"SSH","group_id":group.to_hex(),"rules":[{"id":"ssh","name":"Allow SSH","sources":[{"kind":"machine","id":source.to_hex()}],
        "destinations":[{"kind":"machine","id":destination.to_hex()}],"ports":"22,22","protocol":"tcp"}]})
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn rule_book_changes_are_revision_checked_and_drive_native_policy_preview() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result = async {
        let (owner, cookie) = case.user("books-owner@test.invalid", "user").await?;
        let source = ObjectId::new();
        let destination = ObjectId::new();
        let group = ObjectId::new();
        let original = doc! {"_id":source,"user_id":owner,"name":"Luna","token":"public-token"};
        case.app
            .collection("machines")
            .insert_many([
                original.clone(),
                doc! {"_id":destination,"user_id":owner,"name":"Condor"},
            ])
            .await?;
        case.app
            .collection("machine_groups")
            .insert_one(doc! {"_id":group,"user_id":owner,"name":"Devices"})
            .await?;
        let preview =
            json!({"source_id":source.to_hex(),"destination_id":destination.to_hex(),"port":22});
        let denied = case
            .status(
                "POST",
                "/api/access/test",
                &cookie,
                preview.clone(),
                StatusCode::OK,
            )
            .await?;
        ensure!(
            denied["data"]["allowed"] == false
                && denied["enforcement"] == "policy-preview"
                && denied["transport_ready"] == false
        );
        let input = book(group, source, destination);
        let created = case
            .status(
                "POST",
                "/api/access/books",
                &cookie,
                input.clone(),
                StatusCode::OK,
            )
            .await?;
        ensure!(created["data"]["revision"] == 1 && created["data"]["rules"][0]["ports"] == "22");
        let snapshot = case
            .status(
                "GET",
                "/api/access/snapshot",
                &cookie,
                json!(null),
                StatusCode::OK,
            )
            .await?;
        ensure!(snapshot["books"][0]["created_by"] == owner.to_hex());
        let path = format!(
            "/api/access/books/{}",
            created["data"]["_id"].as_str().unwrap()
        );
        let allowed = case
            .status(
                "POST",
                "/api/access/test",
                &cookie,
                preview.clone(),
                StatusCode::OK,
            )
            .await?;
        ensure!(
            allowed["data"]["allowed"] == true
                && allowed["data"]["rule_id"] == "ssh"
                && allowed["data"]["book_id"] == created["data"]["_id"]
        );
        let reverse =
            json!({"source_id":destination.to_hex(),"destination_id":source.to_hex(),"port":22});
        ensure!(
            case.status(
                "POST",
                "/api/access/test",
                &cookie,
                reverse.clone(),
                StatusCode::OK
            )
            .await?["data"]["allowed"]
                == false
        );
        let mut updated = input.clone();
        updated["revision"] = json!(1);
        updated["rules"][0]["bidirectional"] = json!(true);
        let (a, b) = tokio::join!(
            case.call("PUT", &path, &cookie, updated.clone(), &[]),
            case.call("PUT", &path, &cookie, updated, &[])
        );
        let a = a?;
        let b = b?;
        ensure!(
            (a.0 == StatusCode::OK && b.0 == StatusCode::CONFLICT)
                || (b.0 == StatusCode::OK && a.0 == StatusCode::CONFLICT)
        );
        let saved = if a.0 == StatusCode::OK { a.2 } else { b.2 };
        ensure!(saved["data"]["revision"] == 2);
        ensure!(
            case.status("POST", "/api/access/test", &cookie, reverse, StatusCode::OK)
                .await?["data"]["allowed"]
                == true
        );
        let mut udp = preview.clone();
        udp["protocol"] = json!("udp");
        ensure!(
            case.status("POST", "/api/access/test", &cookie, udp, StatusCode::OK)
                .await?["data"]["allowed"]
                == false
        );
        case.status(
            "DELETE",
            &path,
            &cookie,
            json!({"revision":1}),
            StatusCode::CONFLICT,
        )
        .await?;
        case.status(
            "DELETE",
            &path,
            &cookie,
            json!({"revision":2}),
            StatusCode::OK,
        )
        .await?;
        ensure!(
            case.status("POST", "/api/access/test", &cookie, preview, StatusCode::OK)
                .await?["data"]["allowed"]
                == false
        );
        ensure!(
            case.app
                .collection("machines")
                .find_one(doc! {"_id":source})
                .await?
                .unwrap()
                == original
        );
        Ok(())
    }
    .await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn rule_book_selectors_origin_and_roles_cannot_cross_workspace_boundaries() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result=async {
        let (owner,cookie)=case.user("book-validation-owner@test.invalid","user").await?;
        let (member,member_cookie)=case.user("book-validation-member@test.invalid","user").await?;
        let (foreign,foreign_cookie)=case.user("book-validation-foreign@test.invalid","user").await?;
        case.app.collection("workspace_members").insert_one(doc!{"_id":format!("{owner}:{member}"),"workspace_id":owner,"user_id":member,"role":"member"}).await?;
        let machine=ObjectId::new();let other=ObjectId::new(); let group=ObjectId::new();let foreign_group=ObjectId::new();
        case.app.collection("machines").insert_many([doc!{"_id":machine,"user_id":owner},doc!{"_id":other,"user_id":foreign}]).await?;
        case.app.collection("machine_groups").insert_many([doc!{"_id":group,"user_id":owner},doc!{"_id":foreign_group,"user_id":foreign}]).await?;
        let input=book(group,machine,machine);let path=format!("/api/access/books?workspace={owner}");
        case.status("POST",&path,&member_cookie,input.clone(),StatusCode::FORBIDDEN).await?;
        case.status("POST",&path,&foreign_cookie,input.clone(),StatusCode::FORBIDDEN).await?;
        let (status,_,_)=case.call("POST",&path,&cookie,input.clone(),&[("origin","https://evil.test")]).await?;
        ensure!(status==StatusCode::FORBIDDEN);
        let mut invalid=input.clone();invalid["group_id"]=json!(foreign_group.to_hex());
        case.status("POST",&path,&cookie,invalid,StatusCode::BAD_REQUEST).await?;
        let mut invalid=input.clone();invalid["rules"][0]["sources"][0]["id"]=json!(other.to_hex());
        case.status("POST",&path,&cookie,invalid,StatusCode::BAD_REQUEST).await?;
        let mut invalid=input.clone();invalid["rules"][0]["sources"][0]=json!({"kind":"user","id":foreign.to_hex()});
        case.status("POST",&path,&cookie,invalid,StatusCode::BAD_REQUEST).await?;
        let mut valid=input.clone();valid["rules"][0]["sources"][0]=json!({"kind":"user","id":member.to_hex()});
        let created=case.status("POST",&path,&cookie,valid.clone(),StatusCode::OK).await?;
        let edit=format!("/api/access/books/{}?workspace={owner}",created["data"]["_id"].as_str().unwrap());
        valid["revision"]=json!(1);
        case.status("PUT",&edit,&member_cookie,valid,StatusCode::FORBIDDEN).await?;
        case.status("DELETE",&edit,&member_cookie,json!({"revision":1}),StatusCode::FORBIDDEN).await?;
        let preview=format!("/api/access/test?workspace={owner}");
        case.status("POST",&preview,&member_cookie,json!({"source_id":machine.to_hex(),"destination_id":machine.to_hex()}),StatusCode::OK).await?;
        case.status("POST",&preview,&cookie,json!({"source_id":machine.to_hex(),"destination_id":other.to_hex()}),StatusCode::NOT_FOUND).await?;
        case.status("POST",&path,&cookie,json!({"name":"Bad","group_id":group.to_hex(),"rules":[{}]}),StatusCode::UNPROCESSABLE_ENTITY).await?;
        ensure!(case.app.collection("access_rulebooks").count_documents(doc!{}).await?==1);
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}
